"""Read-only timing experiment for Cyb command 0x69 (MIFARE card information).

Run directly from VS Code or:
    python wcopy_reader_package/tests_and_other/cyb_69_diagnostics.py

Only the library's 0x51 takeover/release and 0x69 card-information commands
are issued. No block reads (0x6C), card writes (0x6A), or LED/beep (0x55).
Uses the existing cyb_speed_diagnostics.Profiler for nested HID timings.
"""
from __future__ import annotations

import argparse
import csv
from datetime import datetime
import json
import logging
import math
from pathlib import Path
import platform
import statistics
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import wcopy_reader as r
from cyb_speed_diagnostics import Profiler

MODES = ("reopen", "reassert", "once")
MODE_NAMES = {
    "reopen": "A: открывать HID заново; подтверждать 51 при каждом опросе",
    "reassert": "B: держать HID открытым; подтверждать 51 при каждом опросе",
    "once": "C: держать HID открытым; подтвердить 51 только в начале серии",
}
CSV_FIELDS = (
    "timestamp", "condition", "mode", "requested_interval_ms", "index",
    "status", "uid_length", "total_ms", "initialize_ms", "poll_69_ms",
    "poll_drain_ms", "poll_usb_write_ms", "poll_usb_read_ms",
    "poll_other_ms", "actual_pause_ms", "error_code", "error_stage", "error",
)


def parse_intervals(raw: str) -> list[float]:
    try:
        values = [float(item.strip()) for item in raw.split(",")]
    except ValueError as error:
        raise ValueError("Интервалы должны быть числами в секундах через запятую") from error
    if not values or any(not math.isfinite(x) or x < 0 or x > 10 for x in values):
        raise ValueError("Каждый интервал должен быть от 0 до 10 секунд")
    return values


def parse_modes(raw: str) -> list[str]:
    values = [item.strip().lower() for item in raw.split(",")]
    if not values or any(value not in MODES for value in values) or len(set(values)) != len(values):
        raise ValueError("Допустимые уникальные режимы: reopen,reassert,once")
    return values


def poll_breakdown(events: list[dict]) -> dict[str, float | None]:
    """Nested timing: drain contains its own HID reads; don't double count."""
    result = dict(initialize_ms=0.0, poll_69_ms=None, poll_drain_ms=None,
                  poll_usb_write_ms=None, poll_usb_read_ms=None, poll_other_ms=None)
    init = [event for event in events if event["name"] == "initialize"]
    result["initialize_ms"] = round(sum(event["ms"] for event in init), 3)
    positions = [index for index, event in enumerate(events) if event["name"].startswith("poll_")]
    if not positions:
        return result
    end = positions[-1]
    poll_ms = events[end]["ms"]
    previous_init = max((i for i in range(end) if events[i]["name"] == "initialize"), default=-1)
    # Events are appended when operations complete. All I/O in this region
    # belongs to 0x69, even when 0x51 was performed earlier in the sample.
    segment = events[previous_init + 1:end]
    drain_ms = sum(e["ms"] for e in segment if e["name"] == "drain")
    last_drain = max((i for i, e in enumerate(segment) if e["name"] == "drain"), default=-1)
    response = segment[last_drain + 1:]
    write_ms = sum(e["ms"] for e in response if e["name"] == "usb_write")
    read_ms = sum(e["ms"] for e in response if e["name"] == "usb_read")
    result.update(poll_69_ms=round(poll_ms, 3),
                  poll_drain_ms=round(drain_ms, 3),
                  poll_usb_write_ms=round(write_ms, 3),
                  poll_usb_read_ms=round(read_ms, 3),
                  poll_other_ms=round(max(0, poll_ms - drain_ms - write_ms - read_ms), 3))
    return result


def measure(profiler: Profiler, action, *, mode: str, condition: str,
            interval: float, index: int, actual_pause_ms=None) -> dict:
    profiler.events = []
    profiler.polls = 0
    started = time.perf_counter()
    row = dict(timestamp=datetime.now().isoformat(timespec="milliseconds"),
               mode=mode, condition=condition, requested_interval_ms=round(interval * 1000, 3),
               index=index, actual_pause_ms=actual_pause_ms, status="error",
               error_code="", error_stage="", error="", uid_length=None)
    try:
        uid, _atqa, _sak = action()
        row["status"] = "card"
        row["uid_length"] = len(uid)
    except r.NoCardError:
        row["status"] = "no_card"
    except r.RFIDError as error:
        row.update(error_code=error.code, error_stage=error.stage, error=str(error))
    except Exception as error:
        row.update(error_code=type(error).__name__, error=str(error))
        logging.exception("Неожиданная ошибка при опросе 69")
    finally:
        row["total_ms"] = round((time.perf_counter() - started) * 1000, 3)
        events = profiler.events or []
        row.update(poll_breakdown(events))
        # Events contain only phase names/timing, not card UID or block contents.
        row["events"] = events
        profiler.events = None
    return row


def percentile90(values: list[float]) -> float:
    ordered = sorted(values)
    return ordered[math.ceil(0.9 * len(ordered)) - 1]


def summarize(rows: list[dict]) -> list[dict]:
    groups = {}
    for row in rows:
        key = (row["condition"], row["mode"], row["requested_interval_ms"])
        groups.setdefault(key, []).append(row)
    result = []
    for (condition, mode, interval_ms), group in groups.items():
        valid = [row for row in group if row["status"] in ("card", "no_card")
                 and row["poll_69_ms"] is not None]
        values = [row["poll_69_ms"] for row in valid]
        reads = [row["poll_usb_read_ms"] for row in valid]
        result.append(dict(
            condition=condition, mode=mode, interval_ms=interval_ms,
            samples=len(group), card=sum(row["status"] == "card" for row in group),
            no_card=sum(row["status"] == "no_card" for row in group),
            errors=sum(row["status"] == "error" for row in group),
            poll_69_median_ms=round(statistics.median(values), 3) if values else None,
            poll_69_p90_ms=round(percentile90(values), 3) if values else None,
            poll_69_min_ms=min(values) if values else None,
            poll_69_max_ms=max(values) if values else None,
            hid_wait_median_ms=round(statistics.median(reads), 3) if reads else None,
        ))
    return result


def collect(profiler, action, *, mode, condition, interval, count, save):
    previous_end = None
    for index in range(1, count + 1):
        actual_pause_ms = (round((time.perf_counter() - previous_end) * 1000, 3)
                           if previous_end is not None else None)
        row = measure(profiler, action, mode=mode, condition=condition,
                      interval=interval, index=index, actual_pause_ms=actual_pause_ms)
        save(row)
        print(f"  {index}/{count} {row['status']}: 69={row['poll_69_ms']} мс, "
              f"USB ожидание={row['poll_usb_read_ms']} мс, "
              f"всё={row['total_ms']} мс")
        if row["status"] == "error":
            print("  Ошибка:", row["error_code"], row["error_stage"], row["error"])
            print("  Серия прервана; команду 69 автоматически не повторяем.")
            return
        previous_end = time.perf_counter()
        if index < count:
            time.sleep(interval)


def run_series(profiler, path, *, mode, condition, interval, count, timeout_ms, save):
    if mode == "reopen":
        def action():
            with r._open_session(path, timeout_ms) as session:
                if not isinstance(session, r._CybSession):
                    raise RuntimeError("Поддерживается только Cyb")
                session.initialize()
                return session._poll()
        collect(profiler, action, mode=mode, condition=condition,
                interval=interval, count=count, save=save)
    elif mode in ("reassert", "once"):
        with r._open_session(path, timeout_ms) as session:
            if not isinstance(session, r._CybSession):
                raise RuntimeError("Поддерживается только Cyb")
            def action():
                if mode == "reassert":
                    # Intentionally reassert 51=01 while retaining the HID handle.
                    session.host_control = False
                session.initialize()
                return session._poll()
            collect(profiler, action, mode=mode, condition=condition,
                    interval=interval, count=count, save=save)
    else:
        raise ValueError("Неизвестный режим")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Замер только команды Cyb 0x69 без чтения/записи блока")
    parser.add_argument("--samples", type=int, default=30, help="Опросов на каждый режим/условие (1..100)")
    parser.add_argument("--intervals", default="0.1", help="Паузы между запросами, секунды: 0,0.1,0.5")
    parser.add_argument("--modes", default="reopen,reassert,once", help="reopen,reassert,once")
    parser.add_argument("--timeout-ms", type=int, default=1500, help="Тайм-аут HID-ответа")
    args = parser.parse_args(argv)
    try:
        intervals = parse_intervals(args.intervals)
        modes = parse_modes(args.modes)
    except ValueError as error:
        parser.error(str(error))
    if not (1 <= args.samples <= 100 and 1 <= args.timeout_ms <= 60000):
        parser.error("samples должен быть 1..100; timeout-ms должен быть 1..60000")

    folder = Path(__file__).resolve().parents[1] / "diagnostics_logs"
    folder.mkdir(parents=True, exist_ok=True)
    stem = folder / ("cyb_69_" + datetime.now().strftime("%Y%m%d_%H%M%S_%f"))
    csv_path, json_path, log_path = (stem.with_suffix(ext) for ext in (".csv", ".json", ".log"))
    logging.basicConfig(filename=str(log_path), level=logging.WARNING, encoding="utf-8",
                        format="%(asctime)s %(levelname)s %(message)s", force=True)
    report = dict(library_version=r.__version__, python=sys.version,
                  platform=platform.platform(), settings=vars(args), samples=[],
                  note="Only 51 and 69; card detection is not a block read. Nested event durations must not be summed.")
    path = None

    def persist():
        report["summary"] = summarize(report["samples"])
        temporary = json_path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(json_path)

    with csv_path.open("w", encoding="utf-8-sig", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=CSV_FIELDS)
        writer.writeheader()
        output.flush()

        def save(row):
            report["samples"].append(row)
            writer.writerow({key: row.get(key) for key in CSV_FIELDS})
            output.flush()
            persist()

        try:
            print("Закройте Master Manager, Cyb_Nfctool, nfcPro и другие программы считывателя.")
            print("Отправляются только 0x51 (управление) и 0x69 (поиск карты).")
            print("Нет записи карты, чтения блока 0x6C и команд звука/LED.")
            readers = [info for info in r.list_readers() if info.backend == "cyb"]
            if not readers:
                raise RuntimeError("Cyb не найден")
            for i, info in enumerate(readers, 1):
                print(i, info.product, f"{info.vendor_id:04X}:{info.product_id:04X}")
            index = int(input("Номер Cyb: ")) if len(readers) > 1 else 1
            if not 1 <= index <= len(readers):
                raise ValueError("Неверный номер устройства")
            info = readers[index - 1]
            path = info.path
            report["reader"] = dict(product=info.product,
                                    vendor_id=info.vendor_id, product_id=info.product_id)
            profiler = Profiler()
            with profiler.instrument():
                for condition, instruction in (
                    ("absent", "Уберите все карты от считывателя"),
                    ("held", "Приложите одну MIFARE Classic и удерживайте неподвижно"),
                ):
                    input(instruction + ", затем нажмите Enter: ")
                    for interval in intervals:
                        for mode in modes:
                            print(f"\n{MODE_NAMES[mode]}; пауза={interval} с; {condition}")
                            run_series(profiler, path, mode=mode, condition=condition,
                                       interval=interval, count=args.samples,
                                       timeout_ms=args.timeout_ms, save=save)
            print("\nМедианы 0x69 (мс):")
            for item in summarize(report["samples"]):
                print(item["condition"], item["mode"], f"пауза={item['interval_ms']} мс:",
                      item["poll_69_median_ms"], f"(ошибок {item['errors']})")
        except KeyboardInterrupt:
            report["interrupted"] = True
            print("\nОстановлено пользователем; результаты сохранены.")
        except Exception as error:
            report["fatal_error"] = repr(error)
            logging.exception("Скрипт диагностики")
            print("Ошибка диагностики:", error)
        finally:
            if path is not None:
                try:
                    report["cleanup_ok"] = r.close_readers(path=path)
                except Exception as error:
                    report["cleanup_ok"] = False
                    report["cleanup_error"] = repr(error)
                    logging.exception("Не удалось вернуть Cyb в автономный режим")
            persist()
            print("\nФайлы для анализа:")
            print(csv_path)
            print(json_path)
            print(log_path)


if __name__ == "__main__":
    main()
