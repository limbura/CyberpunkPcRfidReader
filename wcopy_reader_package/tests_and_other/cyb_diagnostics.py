"""Run directly in VS Code or with Python. Default: identification and READ ONLY."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import argparse
from dataclasses import asdict
from datetime import datetime
import json
import logging
import platform
import traceback
import wcopy_reader as r


def serializable(value):
    if isinstance(value, bytes): return value.hex()
    raise TypeError(type(value).__name__)


def main():
    parser = argparse.ArgumentParser(description='Диагностика Cyb/wCopy; по умолчанию без записи карты')
    parser.add_argument('--write', type=int, metavar='NUMBER', help='Предложить запись числа после чтения и подтверждения')
    args = parser.parse_args()
    folder = Path(__file__).resolve().parents[1] / 'diagnostics_logs'
    folder.mkdir(exist_ok=True)
    stem = folder / ('cyb_' + datetime.now().strftime('%Y%m%d_%H%M%S_%f'))
    logging.basicConfig(filename=str(stem)+'.log', level=logging.DEBUG, encoding='utf-8',
                        format='%(asctime)s %(levelname)s %(message)s')
    report = dict(version=r.__version__, python=sys.version, system=platform.platform(), steps=[])
    def step(name, action):
        try:
            result = action()
            data = asdict(result) if isinstance(result, r.CardData) else result
            report['steps'].append(dict(name=name, result=data))
            print(name + ':', data)
            return result
        except Exception as exc:
            report['steps'].append(dict(name=name, error=str(exc), code=getattr(exc,'code',None),
                                        stage=getattr(exc,'stage',None), traceback=traceback.format_exc()))
            logging.exception(name)
            print(name + ':', getattr(exc,'code',type(exc).__name__), str(exc))
            return None
    try:
        print('Закройте Cyb_Nfctool, nfcPro и другие программы со считывателем.')
        print('Этот запуск только читает карту.' if args.write is None else 'Запись будет предложена отдельно после чтения.')
        hid = r._get_hid()
        # Enumerate metadata for diagnosis; do not open unknown devices or send commands.
        report['hid_devices'] = hid.enumerate()
        readers = r.list_readers()
        report['readers'] = [asdict(x) for x in readers]
        print('Поддерживаемых считывателей:', len(readers))
        for i, reader in enumerate(readers, 1):
            print(f'{i}: {reader.backend} {reader.vendor_id:04X}:{reader.product_id:04X} {reader.product}')
        if not readers:
            print('Устройство не опознано. В отчёт сохранены USB-идентификаторы; команды не отправлялись.')
            return
        index = 0
        if len(readers) > 1:
            index = int(input('Номер считывателя: ')) - 1
            if not 0 <= index < len(readers): raise ValueError('Неверный номер')
        path = readers[index].path
        input('Уберите карту со считывателя и нажмите Enter: ')
        step('without_card', lambda:r.read_card(path=path))
        input('Приложите одну игровую карту MIFARE Classic и нажмите Enter: ')
        card = step('with_card', lambda:r.read_card(path=path))
        if card is not None:
            print('Прочитанное число:', card.number)
            step('repeat_read', lambda:r.read_card(path=path))
        if args.write is not None and card is not None:
            print(f'Будет записано число {args.write} в байты 8..15 блока 1. Текущее число: {card.number}.')
            if input('Не убирая карту, введите ЗАПИСАТЬ для подтверждения: ').strip() == 'ЗАПИСАТЬ':
                step('write', lambda:r.write_card_number(args.write,path=path,
                     expected_uid=card.uid,expected_block=card.block))
        input('Уберите карту и нажмите Enter: ')
        step('removed_card', lambda:r.read_card(path=path))
    except (Exception, KeyboardInterrupt) as exc:
        report['fatal'] = str(exc)
        logging.exception('diagnostics')
        print('Диагностика остановлена:', exc)
    finally:
        Path(str(stem)+'.json').write_text(json.dumps(report,ensure_ascii=False,indent=2,default=serializable),encoding='utf-8')
        logging.shutdown()
        print('Пришлите оба файла:\n'+str(stem)+'.json\n'+str(stem)+'.log')


if __name__ == '__main__': main()
