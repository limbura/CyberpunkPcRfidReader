"""Manual four-byte editor for Cyb indication command 0x55; run in VS Code."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import re
import json
import logging
from datetime import datetime
from dataclasses import asdict
import traceback
import wcopy_reader as r
from cyb_feedback_diagnostics import send_payload


def parse_payload(text):
    parts=text.strip().split()
    decimal=bool(parts and parts[0].lower()=='dec')
    if decimal:parts=parts[1:]
    elif parts and parts[0].lower()=='hex':parts=parts[1:]
    pattern=r'[0-9]{1,3}' if decimal else r'(?:0[xX])?[0-9a-fA-F]{1,2}'
    if len(parts)!=4 or any(re.fullmatch(pattern,p) is None for p in parts):
        raise ValueError('Введите 4 HEX-байта: 01 03 01 00; или dec 1 3 1 0')
    values=[int(p,10 if decimal else 16) for p in parts]
    if any(v>255 for v in values):raise ValueError('Каждый байт должен быть от 0 до 255 (00..FF)')
    return bytes(values)


def main():
    folder=Path(__file__).resolve().parents[1]/'diagnostics_logs'
    folder.mkdir(exist_ok=True)
    stem=folder/('cyb_manual_'+datetime.now().strftime('%Y%m%d_%H%M%S_%f'))
    report=dict(version=r.__version__,diagnostic_version=1,events=[])
    logging.basicConfig(filename=str(stem)+'.log',encoding='utf-8',level=logging.DEBUG,
                        format='%(asctime)s %(levelname)s %(message)s')
    def save():
        Path(str(stem)+'.json').write_text(json.dumps(report,ensure_ascii=False,indent=2,
            default=lambda x:x.hex() if isinstance(x,bytes) else str(x)),encoding='utf-8')
    try:
        print('Cyb: ручная команда звука/света 0x55. Закройте другие программы со считывателем.')
        print('Введите 4 HEX-байта и Enter — отправка сразу. Например: 01 01 01 00')
        print('Десятичный ввод: dec 1 3 1 0. Пустая строка ничего не отправляет.')
        print('on — управление с ПК; off — автономный режим; q — выход.')
        print('По умолчанию управление с ПК не включается. Карты не читаются и не записываются.')
        print('Если сигнал затянется, отключите USB: подтверждённой команды остановки пока нет.')
        readers=[x for x in r.list_readers() if x.backend=='cyb']
        if not readers:raise RuntimeError('Cyb не найден')
        for i,x in enumerate(readers,1):print(f'{i}: {x.product} {x.vendor_id:04X}:{x.product_id:04X}')
        index=int(input('Номер считывателя: '))-1 if len(readers)>1 else 0
        if not 0<=index<len(readers):raise ValueError('Неверный номер')
        reader=readers[index];report['reader']=asdict(reader);save()
        with r._open_session(reader.path,2500) as session:
            while True:
                text=input('\nЧетыре байта / on / off / q: ').strip()
                if text.lower() in ('q','quit','exit'):break
                if not text:continue
                if text.lower() in ('on','off'):
                    event=dict(time=datetime.now().astimezone().isoformat(),action=text.lower())
                    report['events'].append(event);save()
                    if text.lower()=='on':session.initialize()
                    else:
                        # Explicit off is also useful after another application;
                        # release sends 51=0 and validates its echo.
                        session.host_requested=True
                        session.release()
                    event['result']='ok';save();print('Режим переключён.');continue
                try:payload=parse_payload(text)
                except ValueError as exc:print(exc);continue
                frame=r._cyb_request(0x55,payload)
                print('Параметры HEX:',payload.hex(' ').upper())
                print('Параметры DEC:',*payload)
                print('Пакет команды:',frame.hex(' ').upper())
                event=dict(time=datetime.now().astimezone().isoformat(),action='indication',
                    payload=payload.hex(' '),host_control=session.host_control,frame=frame.hex(' '))
                report['events'].append(event);save()
                event['transport']=send_payload(session,payload);save()
                print('Отправлено один раз. Ответов USB:',len(event['transport']['replies']))
                print('Отсутствие ответа допустимо; результат определяем по звуку и LED.')
                event['observation']=input('Что произошло со звуком и LED? (Enter — пропустить): ')
                logging.info('payload=%s observation=%s',payload.hex(' '),event['observation']);save()
    except (Exception,KeyboardInterrupt) as exc:
        report['error']=str(exc);report['traceback']=traceback.format_exc()
        logging.exception('manual diagnostics stopped');print('Остановлено:',exc)
    finally:
        save();logging.shutdown()
        print('Журналы:\n'+str(stem)+'.json\n'+str(stem)+'.log')


if __name__=='__main__':main()
