"""Interactive Cyb indication study. Only host-control (51) and indication (55).

No card poll, authentication, read, write, reset or firmware commands.
Run directly in VS Code. Observe sound/light, not just USB responses.
"""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dataclasses import asdict
from datetime import datetime
import json
import logging
import time
import traceback
import wcopy_reader as r

ORIGINAL = (
    ('double', 'Двойной сигнал из оригинальной программы', bytes.fromhex('01 01 02 00')),
    ('long', 'Длинный сигнал из оригинальной программы', bytes.fromhex('00 05 01 00')),
)
VARIANTS = (
    ('count_one', 'Проверка третьего байта: 02 → 01', bytes.fromhex('01 01 01 00')),
    ('duration_one', 'Проверка второго байта: 05 → 01', bytes.fromhex('00 01 01 00')),
    ('duration_three', 'Проверка второго байта: 01 → 03', bytes.fromhex('00 03 01 00')),
)


def probe(session, payload):
    """Send exactly one indication request, capture optional replies for 1 second.

    Vendor wrappers are fire-and-forget. No reply is not treated as failure,
    and no retry is performed. Observed sound/light is recorded by the user.
    """
    if payload not in {p for _, _, p in ORIGINAL + VARIANTS}:
        raise ValueError('Пакет вне фиксированного набора диагностики')
    return send_payload(session, payload)


def send_payload(session, payload):
    """Send exactly four user-selected bytes to indication command 0x55 only."""
    if not isinstance(payload, bytes) or len(payload) != 4:
        raise ValueError('Нужно ровно 4 байта параметров индикации')
    session._drain('feedback_probe')
    frame = r._cyb_request(0x55, payload)
    report = b'\0' + frame
    logging.debug('feedback_probe CYB TX %s', report.hex(' '))
    try:
        written = session.device.write(report)
        logging.debug('feedback_probe requested=%d returned=%s', len(report), written)
        if written not in (len(report), 65):
            raise r.USBError(f'Результат write={written}; ожидалось {len(report)} или 65', stage='feedback_probe')
        result = dict(payload=payload.hex(' '), requested=len(report), written=written, replies=[])
        deadline = time.monotonic() + 1.0
        for _ in range(32):
            remaining = int((deadline-time.monotonic())*1000)
            if remaining <= 0: break
            raw = bytes(session.device.read(65, remaining))
            if not raw: break
            logging.debug('feedback_probe CYB RX %s', raw.hex(' '))
            result['replies'].append(raw.hex(' '))
        return result
    except OSError as exc:
        raise r.USBError(str(exc), stage='feedback_probe') from exc


def main():
    folder = Path(__file__).resolve().parents[1] / 'diagnostics_logs'
    folder.mkdir(exist_ok=True)
    stem = folder / ('cyb_feedback_' + datetime.now().strftime('%Y%m%d_%H%M%S_%f'))
    logging.basicConfig(filename=str(stem)+'.log', encoding='utf-8', level=logging.DEBUG,
                        format='%(asctime)s %(levelname)s %(message)s')
    result = dict(version=r.__version__, diagnostic_version=1, observations=[], runs=[])
    def observe(label):
        answer = input(label + '\nОтвет (например: «2 коротких писка, LED красный без изменений»): ')
        result['observations'].append(dict(label=label, answer=answer))
        logging.info('Observation %s: %s',label,answer)
    try:
        print('Закройте Cyb_Nfctool и другие программы со считывателем.')
        print('Карты не читаются и не записываются. Команды: только управление с ПК и индикация.')
        print('Первые 3 байта исходных режимов взяты из EXE; четвёртый там не задан явно, здесь он равен 0.')
        print('Для выхода в любой момент: Ctrl+C. Никакой команды не повторяем автоматически.')
        print('Сначала переподключите USB. Пока никаких команд от скрипта нет.')
        observe('Приложите и уберите карту один раз. Что происходило со звуком и LED?')
        input('Теперь уберите все карты и нажмите Enter: ')
        readers = [x for x in r.list_readers() if x.backend=='cyb']
        if not readers: raise RuntimeError('Cyb не найден')
        for i, reader in enumerate(readers,1):print(f'{i}: {reader.product} {reader.vendor_id:04X}:{reader.product_id:04X}')
        index = int(input('Номер считывателя: '))-1 if len(readers)>1 else 0
        if not 0<=index<len(readers):raise ValueError('Неверный номер')
        reader=readers[index]
        result['reader']=asdict(reader)
        while True:
            print('\n1 — два исходных сигнала, управление с ПК')
            print('2 — два исходных сигнала, без включения управления с ПК')
            print('3 — три малых изменения параметров, управление с ПК (после группы 1)')
            print('0 — сохранить журналы и выйти')
            choice=input('Выбор: ').strip()
            if choice=='0':break
            if choice not in ('1','2','3'):continue
            run=dict(group=choice, probes=[]);result['runs'].append(run)
            input('Карт на считывателе быть не должно. Нажмите Enter: ')
            with r._open_session(reader.path,2500) as session:
                if choice!='2':
                    session.initialize()
                    observe('Только включили управление с ПК, команд писка ещё не было. Были изменения?')
                else:
                    observe('Только открыли USB, без команд. Были изменения?')
                for name,label,payload in (VARIANTS if choice=='3' else ORIGINAL):
                    input(f'Enter — {label}, пакет {payload.hex(" ")}: ')
                    record=dict(name=name);run['probes'].append(record)
                    record.update(probe(session,payload))
                    observe('Команда отправлена. Что слышно и что происходит с LED?')
            observe('Сеанс закрыт (после управления с ПК отправлен возврат в автономный режим). Есть изменения?')
        print('После завершения можно снова приложить карту и проверить штатной двойной писк.')
    except (Exception, KeyboardInterrupt) as exc:
        result['error']=str(exc)
        result['traceback']=traceback.format_exc()
        logging.exception('feedback diagnostics stopped')
        print('Диагностика остановлена:',exc)
    finally:
        Path(str(stem)+'.json').write_text(json.dumps(result,ensure_ascii=False,indent=2,
                     default=lambda x:x.hex() if isinstance(x,bytes) else str(x)),encoding='utf-8')
        logging.shutdown()
        print('Пришлите оба файла:\n'+str(stem)+'.json\n'+str(stem)+'.log')


if __name__=='__main__':main()
