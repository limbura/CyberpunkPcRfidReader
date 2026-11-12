"""Read-only Cyb timing comparison. Run directly in VS Code; no extra dependencies."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import argparse
from contextlib import contextmanager
from datetime import datetime
import json
import logging
import platform
import statistics
import time
from unittest.mock import patch
import wcopy_reader as r

MODES = ('standard', 'open_reassert', 'open_once')
LABELS = {
    'standard': 'A: текущая библиотека, открыть/закрыть USB на каждом чтении',
    'open_reassert': 'B: USB открыт постоянно, 51=01 перед каждым чтением',
    'open_once': 'C: USB открыт постоянно, 51=01 только перед первым чтением',
}


class Profiler:
    def __init__(self):
        self.events = None
        self.polls = 0

    def call(self, name, action, **metadata):
        start = time.perf_counter()
        event = dict(name=name, **metadata)
        try:
            return action()
        except BaseException as error:
            event['error'] = type(error).__name__
            raise
        finally:
            event['ms'] = round((time.perf_counter() - start)*1000, 3)
            if self.events is not None:
                self.events.append(event)

    @contextmanager
    def instrument(self):
        profiler = self
        hid = r._get_hid()
        exchange = r._CybSession.exchange_cyb
        drain = r._CybSession._drain

        class DeviceProxy:
            def __init__(self, device): self.device = device
            def __getattr__(self, key): return getattr(self.device, key)
            def open_path(self, path):
                return profiler.call('usb_open', lambda: self.device.open_path(path))
            def close(self):
                return profiler.call('usb_close', self.device.close)
            def write(self, report):
                return profiler.call('usb_write', lambda: self.device.write(report), size=len(report))
            def read(self, size, timeout_ms):
                return profiler.call('usb_read', lambda: self.device.read(size, timeout_ms), timeout_ms=timeout_ms)

        class HidProxy:
            def enumerate(self, *args):
                return profiler.call('enumerate', lambda: hid.enumerate(*args))
            def device(self):
                return DeviceProxy(profiler.call('usb_device', hid.device))

        def timed_exchange(session, command, payload, stage):
            name = stage
            if command == 0x69:
                profiler.polls += 1
                name = f'poll_{profiler.polls}'
            return profiler.call(name, lambda: exchange(session, command, payload, stage), command=command)

        def timed_drain(session, stage):
            return profiler.call('drain', lambda: drain(session, stage), stage=stage)

        with patch.object(r, '_get_hid', return_value=HidProxy()), \
             patch.object(r._CybSession, 'exchange_cyb', timed_exchange), \
             patch.object(r._CybSession, '_drain', timed_drain):
            yield

    def sample(self, action, *, mode, condition, index):
        self.events = []
        self.polls = 0
        start = time.perf_counter()
        row = dict(mode=mode, condition=condition, index=index,
                   started=datetime.now().isoformat(timespec='milliseconds'))
        try:
            card = action()
            row.update(status='card', uid=card.uid.hex(), number=card.number)
        except r.NoCardError:
            row['status'] = 'no_card'
        except r.RFIDError as error:
            row.update(status='error', error=str(error), code=error.code, stage=error.stage)
        finally:
            row['total_ms'] = round((time.perf_counter() - start)*1000, 3)
            row['events'] = self.events
            self.events = None
        return row


def totals(row):
    result = {}
    for event in row['events']:
        result[event['name']] = result.get(event['name'], 0) + event['ms']
    return result


def run_mode(profiler, path, mode, condition, count, timeout_ms, interval, save):
    """No writes or indication; both UID polls remain in _CybSession.read()."""
    def collect(action):
        for index in range(1, count+1):
            row = profiler.sample(action, mode=mode, condition=condition, index=index)
            save(row)
            parts = totals(row)
            print(f"  {index}/{count}: {row['status']}, всего {row['total_ms']:.0f} мс; "
                  f"51={parts.get('initialize', 0):.0f}, поиск={parts.get('poll_1', 0):.0f}, "
                  f"блок={parts.get('read', 0):.0f}, проверка UID={parts.get('poll_2', 0):.0f} мс")
            if row['status'] == 'error':
                # Do not continue a retained session after a protocol/USB error.
                print('  Ошибка:', row['code'], row['stage'], row['error'])
                print('  Этот режим остановлен; ошибка включена в отчёт.')
                break
            if index < count:
                time.sleep(interval)

    if mode == 'standard':
        collect(lambda: r.read_card(path=path, timeout_ms=timeout_ms, auto_feedback=False))
    elif mode in ('open_reassert', 'open_once'):
        # Setup excluded from per-read totals in B/C; separately saved below.
        setup_start = time.perf_counter()
        with r._open_session(path, timeout_ms) as session:
            if not isinstance(session, r._CybSession):
                raise ValueError('Диагностика предназначена только для Cyb')
            save(dict(mode=mode, condition=condition, status='setup',
                      total_ms=round((time.perf_counter()-setup_start)*1000, 3), events=[]))
            def read():
                if mode == 'open_reassert': session.host_control = False
                return session.read()
            collect(read)
    else:
        raise ValueError('Неизвестный режим')


def summary(rows):
    result = []
    for condition in ('absent', 'held'):
        for mode in MODES:
            samples = [x for x in rows if x['mode'] == mode and x['condition'] == condition
                       and x['status'] in ('card', 'no_card')]
            if not samples: continue
            values = [x['total_ms'] for x in samples]
            result.append(dict(condition=condition, mode=mode, samples=len(values),
                               median_ms=round(statistics.median(values), 3),
                               min_ms=min(values), max_ms=max(values)))
    return result


def main():
    parser = argparse.ArgumentParser(description='Замеры Cyb без записи карты и без писка')
    parser.add_argument('--samples', type=int, default=5)
    parser.add_argument('--timeout-ms', type=int, default=2500)
    parser.add_argument('--interval', type=float, default=0.25)
    args = parser.parse_args()
    import math
    if not 1 <= args.samples <= 100 or not 1 <= args.timeout_ms <= 60000 or not math.isfinite(args.interval) or not 0 <= args.interval <= 10:
        parser.error('samples: 1..100; timeout-ms: 1..60000; interval: 0..10')
    folder = Path(__file__).resolve().parents[1] / 'diagnostics_logs'
    folder.mkdir(exist_ok=True)
    stem = folder / ('cyb_speed_' + datetime.now().strftime('%Y%m%d_%H%M%S_%f'))
    report = dict(version=r.__version__, python=sys.version, system=platform.platform(),
                  settings=vars(args), samples=[], note='USB timings include nested events; do not sum all events.')
    logging.basicConfig(filename=str(stem)+'.log', level=logging.DEBUG, encoding='utf-8',
                        format='%(asctime)s %(levelname)s %(message)s', force=True)
    def persist():
        report['summary'] = summary(report['samples'])
        stem.with_suffix('.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    def save(row):
        report['samples'].append(row)
        persist()
    path = None
    try:
        print('Закройте Master Manager, Cyb_Nfctool и другие программы считывателя.')
        print('Скрипт только читает. Записи и звука нет. Проверки UID не отключаются.')
        readers = [x for x in r.list_readers() if x.backend == 'cyb']
        if not readers: raise RuntimeError('Подключённый Cyb не найден')
        for index, reader in enumerate(readers, 1):
            print(index, reader.product, reader.path)
        choice = int(input('Номер Cyb: ')) if len(readers) > 1 else 1
        if not 1 <= choice <= len(readers): raise ValueError('Неверный номер')
        reader = readers[choice-1]
        path = reader.path
        report['reader'] = dict(path=path.hex(), vendor_id=reader.vendor_id, product_id=reader.product_id, product=reader.product)
        profiler = Profiler()
        with profiler.instrument():
            for condition, instruction in [('absent', 'Уберите карту'), ('held', 'Приложите одну карту и оставьте неподвижно')]:
                input(instruction + '. Нажмите Enter: ')
                for mode in MODES:
                    print(LABELS[mode])
                    run_mode(profiler, path, mode, condition, args.samples, args.timeout_ms, args.interval, save)
        print('\nМедиана времени полного чтения/опроса, мс:')
        for row in summary(report['samples']):
            print(row['condition'], row['mode'], row['median_ms'])
        print('Это время операции, не точный замер от движения руки до реакции.')
    except KeyboardInterrupt:
        report['interrupted'] = True
        print('\nОстановлено; частичные результаты сохранены.')
    except Exception as error:
        report['fatal_error'] = repr(error)
        logging.exception('Диагностика остановлена')
        print('Ошибка:', error)
    finally:
        if path is not None: report['cleanup_ok'] = r.close_readers(path=path)
        persist()
        print('Пришлите оба файла:')
        print(stem.with_suffix('.json'))
        print(stem.with_suffix('.log'))


if __name__ == '__main__':
    main()
