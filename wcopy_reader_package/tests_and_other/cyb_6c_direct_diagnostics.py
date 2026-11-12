"""Read-only Cyb experiment: does 0x6C work without a preceding 0x69?

Run from VS Code or from repository root:
    python wcopy_reader_package/tests_and_other/cyb_6c_direct_diagnostics.py

Requires two MIFARE Classic test cards with DIFFERENT block 1 contents.
Sends only host control 0x51, card info 0x69 for control samples, and
read block 0x6C. It NEVER writes a block, plays a sound, or alters a tag.

Private library functions are intentionally used only in this diagnostic.
"""
from __future__ import annotations

import argparse
import csv
from datetime import datetime
import hashlib
import hmac
import json
import logging
from pathlib import Path
import platform
import secrets
import statistics
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import wcopy_reader as r
from cyb_speed_diagnostics import Profiler

COLUMNS = (
    "timestamp", "phase", "sample", "kind", "status", "total_ms",
    "read_6c_ms", "poll_69_ms", "mask", "response_len",
    "block_tag", "uid_tag", "error_code", "error_stage", "error",
)
PHASES = (
    ("A_direct_first", "A", "Переподключите USB Cyb, приложите карту A и держите её неподвижно. Это будет первая проверка, ДО любого 0x69.", "direct"),
    ("A_reference", "A", "Продолжайте удерживать карту A. Теперь контрольное 0x69 → 0x6C.", "reference"),
    ("A_direct_after", "A", "Не убирайте карту A. Повторяем прямое 0x6C после 0x69.", "direct"),
    ("A_removed", "none", "Уберите карту A и держите антенну пустой.", "direct"),
    ("B_direct_before_info", "B", "Приложите ДРУГУЮ карту B, не прикладывая A. Перед этим блоком нового 0x69 не будет.", "direct"),
    ("B_reference", "B", "Не убирайте карту B. Контрольное 0x69 → 0x6C для сравнения.", "reference"),
    ("A_direct_return", "A", "Уберите B и верните карту A. Снова пробуем 0x6C БЕЗ нового 0x69.", "direct"),
    ("A_reference_return", "A", "Удерживайте карту A. Финальная контрольная проверка 0x69 → 0x6C.", "reference"),
)


def private_tag(key: bytes, value: bytes) -> str:
    """Anonymous run-local label: no raw UID, block or card number in report."""
    return hmac.new(key, value, hashlib.sha256).hexdigest()[:16]


def decode_read_response(body: bytes, key: bytes) -> dict:
    result = {"response_len": len(body), "mask": None, "block_tag": None}
    if len(body) < 4:
        return dict(result, status="invalid_response")
    mask = int.from_bytes(body[:4], "big")
    result["mask"] = mask
    if mask != 1:
        return dict(result, status="read_failed")
    if len(body) != 20:
        return dict(result, status="invalid_response")
    return dict(result, status="read_ok", block_tag=private_tag(key, body[4:20]))


def direct_read(session: r._CybSession, key: bytes) -> dict:
    # IMPORTANT: No implicit UID poll in this code path!
    body = session.exchange_cyb(0x6C, session._block_parameters(), "read")
    return decode_read_response(body, key)


def reference_read(session: r._CybSession, key: bytes) -> dict:
    uid, atqa, sak = session._poll()   # Exactly one 0x69, only in reference phases.
    result = direct_read(session, key)
    result["uid_tag"] = private_tag(key, uid)
    result["uid_length"] = len(uid)
    result["sak"] = sak
    return result


def measure(profiler: Profiler, action, *, phase: str, sample: int, kind: str) -> dict:
    profiler.events = []
    profiler.polls = 0
    start = time.perf_counter()
    row = {"timestamp": datetime.now().isoformat(timespec="milliseconds"),
           "phase": phase, "sample": sample, "kind": kind, "status": "error",
           "mask": None, "response_len": None, "block_tag": None, "uid_tag": None,
           "error_code": "", "error_stage": "", "error": ""}
    try:
        row.update(action())
    except r.RFIDError as exc:
        row.update(status="error", error_code=exc.code,
                   error_stage=exc.stage, error=str(exc))
    except Exception as exc:
        row.update(status="error", error_code=type(exc).__name__, error=str(exc))
        logging.exception("Unexpected error in %s", phase)
    finally:
        row["total_ms"] = round((time.perf_counter() - start) * 1000, 3)
        events = profiler.events or []
        row["read_6c_ms"] = next((event["ms"] for event in reversed(events)
                                 if event.get("command") == 0x6C), None)
        row["poll_69_ms"] = next((event["ms"] for event in reversed(events)
                                 if event.get("command") == 0x69), None)
        row["events"] = events
        profiler.events = None
    return row


def collect(profiler, session, key, *, phase: str, kind: str, samples: int,
            interval: float, save) -> bool:
    action = (lambda: direct_read(session, key)) if kind == "direct" else (
        lambda: reference_read(session, key))
    for index in range(1, (samples if kind == "direct" else 1) + 1):
        row = measure(profiler, action, phase=phase, sample=index, kind=kind)
        save(row)
        print(f"  {index}: {row['status']} 6C={row['read_6c_ms']} мс "
              f"69={row['poll_69_ms']} мс блок={row['block_tag'] or '-'} "
              f"маска={row['mask']}")
        if row["status"] == "error":
            # A timed-out command may finish later. No automatic retry of it.
            print("  ОШИБКА / ТАЙМ-АУТ. Серия остановлена, чтобы исключить "
                  "подмену ответов запоздавшими пакетами.")
            return False
        if index < samples and kind == "direct":
            time.sleep(interval)
    return True


def analyze(rows: list[dict]) -> dict:
    phases = {}
    for row in rows:
        phases.setdefault(row["phase"], []).append(row)
    summary = {}
    for phase, group in phases.items():
        values = [row["read_6c_ms"] for row in group
                  if row["read_6c_ms"] is not None]
        summary[phase] = dict(
            count=len(group),
            ok=sum(row["status"] == "read_ok" for row in group),
            failed=sum(row["status"] == "read_failed" for row in group),
            errors=sum(row["status"] in ("error", "invalid_response") for row in group),
            median_read_ms=round(statistics.median(values), 3) if values else None,
            tags=sorted({row["block_tag"] for row in group if row["block_tag"]}),
        )
    refs = {p: next((x for x in phases.get(p, []) if x["status"] == "read_ok"), None)
            for p in ("A_reference", "B_reference", "A_reference_return")}
    warnings = []
    a, b, a2 = refs["A_reference"], refs["B_reference"], refs["A_reference_return"]
    if a is None or b is None:
        warnings.append("Нет контрольных успешных чтений A и B: автоматически оценить смену карты нельзя.")
    else:
        if a["uid_tag"] == b["uid_tag"]:
            warnings.append("Контроль A/B показал одинаковый UID: нужны две РАЗНЫЕ карты.")
        if a["block_tag"] == b["block_tag"]:
            warnings.append("Блоки A/B совпадают: команда 6C не позволяет различить их по содержимому.")
        if a["uid_tag"] != b["uid_tag"] and a["block_tag"] != b["block_tag"]:
            for p, ref in (("A_direct_first", a), ("A_direct_after", a),
                           ("B_direct_before_info", b), ("A_direct_return", a)):
                seen = [x for x in phases.get(p, []) if x["status"] == "read_ok"]
                if seen and any(x["block_tag"] != ref["block_tag"] for x in seen):
                    warnings.append(p + ": 0x6C возвращает НЕ ТОТ блок — возможен кэш или неверный выбор карты.")
                if not seen:
                    warnings.append(p + ": не получено успешных прямых чтений 0x6C.")
        if a2 is not None and (a2["uid_tag"] != a["uid_tag"]
                               or a2["block_tag"] != a["block_tag"]):
            warnings.append("Контрольная карта A после возврата не совпала с исходной A.")
    if any(x["status"] == "read_ok" for x in phases.get("A_removed", [])):
        warnings.append("КРИТИЧНО: 0x6C вернула успешное чтение при снятой карте A.")
    return {"by_phase": summary, "warnings": warnings,
            "note": "A successful 0x6C never returns UID. A read failure is not proof of no card."}


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="Диагностика прямой команды Cyb 0x6C без 0x69")
    parser.add_argument("--samples", type=int, default=8,
                        help="Число прямых чтений за фазу (1..50)")
    parser.add_argument("--interval", type=float, default=0.1,
                        help="Пауза между операциями в секундах (0..5)")
    parser.add_argument("--timeout-ms", type=int, default=1500)
    args = parser.parse_args(argv)
    import math
    if not (1 <= args.samples <= 50 and math.isfinite(args.interval)
            and 0 <= args.interval <= 5 and 1 <= args.timeout_ms <= 60000):
        parser.error("samples: 1..50; interval: 0..5; timeout-ms: 1..60000")

    folder = Path(__file__).resolve().parents[1] / "diagnostics_logs"
    folder.mkdir(exist_ok=True)
    stem = folder / ("cyb_6c_" + datetime.now().strftime("%Y%m%d_%H%M%S_%f"))
    csv_path, json_path, log_path = (stem.with_suffix(ext)
                                     for ext in (".csv", ".json", ".log"))
    logging.basicConfig(filename=str(log_path), level=logging.WARNING,
                        encoding="utf-8", format="%(asctime)s %(levelname)s %(message)s",
                        force=True)
    secret = secrets.token_bytes(32)
    report = dict(version=r.__version__, settings=vars(args),
                  platform=platform.platform(), samples=[], partial=True,
                  note="Anonymized tags are comparable ONLY within this run; UID/card data never saved.")
    selected_path = None

    def persist():
        report["analysis"] = analyze(report["samples"])
        temp = json_path.with_suffix(".json.tmp")
        temp.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        temp.replace(json_path)

    with csv_path.open("w", encoding="utf-8-sig", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=COLUMNS)
        writer.writeheader()
        out.flush()

        def save(row):
            report["samples"].append(row)
            writer.writerow({column: row.get(column) for column in COLUMNS})
            out.flush()
            persist()

        try:
            print("Закройте Master Manager, nfcPro и Cyb_Nfctool.")
            print("Подготовьте ДВЕ РАЗНЫЕ MIFARE Classic с разными ID в блоке 1.")
            print("Диагностика отправляет ТОЛЬКО 51, 6C и контрольную 69.")
            print("НИКАКИХ команд записи, звука и изменения содержимого карты.")
            input("Для проверки холодного старта: переподключите Cyb к USB, "
                  "положите карту A, затем нажмите Enter: ")
            readers = [reader for reader in r.list_readers() if reader.backend == "cyb"]
            if not readers:
                raise RuntimeError("Подключённый Cyb не найден")
            for i, reader in enumerate(readers, 1):
                print(i, reader.product, f"{reader.vendor_id:04X}:{reader.product_id:04X}")
            n = int(input("Номер Cyb: ")) if len(readers) > 1 else 1
            if n < 1 or n > len(readers):
                raise ValueError("Неправильный номер Cyb")
            selected_path = readers[n - 1].path
            report["reader"] = dict(vid=readers[n - 1].vendor_id,
                                    pid=readers[n - 1].product_id)
            profiler = Profiler()
            with profiler.instrument():
                with r._open_session(selected_path, args.timeout_ms) as session:
                    if not isinstance(session, r._CybSession):
                        raise RuntimeError("Только Cyb")
                    session.initialize()
                    for phase, card, prompt, kind in PHASES:
                        if phase != "A_direct_first":
                            input("\n" + prompt + "\nНажмите Enter: ")
                        print(f"\n{phase}: {kind}")
                        ok = collect(profiler, session, secret, phase=phase, kind=kind,
                                     samples=args.samples, interval=args.interval,
                                     save=save)
                        if not ok:
                            report["stopped_at"] = phase
                            print("Остановлено: после тайм-аута/ошибки продолжать на "
                                  "том же USB-сеансе небезопасно для достоверности.")
                            break
                    else:
                        report["partial"] = False
            print("\nРезультат:")
            for name, stats in report.get("analysis", {}).get("by_phase", {}).items():
                print(name, stats)
            for warning in report.get("analysis", {}).get("warnings", []):
                print("ВНИМАНИЕ:", warning)
        except KeyboardInterrupt:
            report["interrupted"] = True
            print("\nОстановлено пользователем.")
        except Exception as exc:
            report["fatal_error"] = repr(exc)
            logging.exception("Диагностика 6C")
            print("Ошибка диагностики:", exc)
        finally:
            if selected_path is not None:
                try:
                    report["cleanup_ok"] = r.close_readers(path=selected_path)
                except Exception as exc:
                    report["cleanup_ok"] = False
                    report["cleanup_error"] = str(exc)
                    logging.exception("Ошибка освобождения управления")
            persist()
            print("\nПришлите CSV и JSON:")
            print(csv_path)
            print(json_path)
            print("LOG при нормальном завершении может быть пуст:", log_path)


if __name__ == "__main__":
    main()
