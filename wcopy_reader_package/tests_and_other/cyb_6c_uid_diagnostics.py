"""Read-only hardware test: obtain MIFARE Classic UID from manufacturer block 0.

Run from the repository root:
    python wcopy_reader_package/tests_and_other/cyb_6c_uid_diagnostics.py

Only commands: 0x51 (host control), 0x6C (read), 0x69 (reference UID).
NO tag writes, no card formatting, and no feedback commands.
Neither UID bytes nor manufacturer/user blocks are saved into reports.
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

KEYS = b"\xff" * 12
FIELDS = (
    "timestamp", "card", "phase", "status", "ms", "mask", "response_len",
    "uid_length", "uid_match", "bcc4_ok", "uid_tag", "block0_tag",
    "block1_tag", "sak", "error_code", "error_stage", "error",
)


def parameters(start: int, count: int) -> bytes:
    if (start, count) not in ((0, 1), (0, 2), (1, 1)):
        raise ValueError("Only read operations (0,1), (0,2), (1,1) are allowed")
    return bytes((start, count, 0)) + KEYS


def tag(secret: bytes, data: bytes) -> str:
    return hmac.new(secret, data, hashlib.sha256).hexdigest()[:16]


def decode_read(body: bytes, start: int, count: int, secret: bytes) -> dict:
    result = {"response_len": len(body), "mask": None, "block0_tag": None,
              "block1_tag": None, "status": "invalid_response"}
    if len(body) < 4:
        return result
    mask = int.from_bytes(body[:4], "big")
    result["mask"] = mask
    if mask != (1 << count) - 1:
        result["status"] = "read_failed" if mask == 0 else "partial_read"
        return result
    expected = 4 + count * 16
    if len(body) != expected:
        return result
    blocks = [body[4 + i * 16:4 + (i + 1) * 16] for i in range(count)]
    for i, block in enumerate(blocks):
        result["block" + str(start + i) + "_tag"] = tag(secret, block)
    result["status"] = "read_ok"
    return result


def compare_uid(block0: bytes, uid: bytes, secret: bytes) -> dict:
    """Manufacturer block candidate only; cross-check against 0x69."""
    n = len(uid)
    if n not in (4, 7) or len(block0) != 16:
        return {"uid_length": n, "uid_match": None, "bcc4_ok": None,
                "uid_tag": tag(secret, uid)}
    candidate = block0[:n]
    # Manufacturer block with 4-byte UID: BCC = UID0 xor UID1 xor UID2 xor UID3.
    bcc = (candidate[0] ^ candidate[1] ^ candidate[2] ^ candidate[3] ==
           block0[4]) if n == 4 else None
    return {"uid_length": n, "uid_match": candidate == uid, "bcc4_ok": bcc,
            "uid_tag": tag(secret, uid)}


def decode_block(body: bytes, start: int, count: int) -> list[bytes] | None:
    """Only expose raw block bytes in memory to compare, never write to disk."""
    if len(body) != 4 + 16 * count:
        return None
    if int.from_bytes(body[:4], "big") != (1 << count) - 1:
        return None
    return [body[4 + i * 16:4 + (i + 1) * 16] for i in range(count)]


def read(session, start: int, count: int) -> bytes:
    return session.exchange_cyb(0x6C, parameters(start, count), "read")


def perform(session, secret: bytes, card: str, phase: str, action, *,
            start=None, count=None) -> tuple[dict, bytes | None]:
    row = {
        "timestamp": datetime.now().isoformat(timespec="milliseconds"),
        "card": card, "phase": phase, "status": "error",
        "ms": None, "mask": None, "response_len": None,
        "uid_length": None, "uid_match": None, "bcc4_ok": None,
        "uid_tag": None, "block0_tag": None, "block1_tag": None, "sak": None,
        "error_code": "", "error_stage": "", "error": "",
    }
    raw = None
    started = time.perf_counter()
    try:
        raw = action()
        if start is not None:
            row.update(decode_read(raw, start, count, secret))
        else:
            uid, atqa, sak = raw
            row.update(status="uid_ok", uid_length=len(uid), uid_tag=tag(secret, uid),
                       sak=sak)
    except r.RFIDError as exc:
        row.update(status="error", error_code=exc.code, error_stage=exc.stage,
                   error=str(exc))
    except Exception as exc:
        row.update(status="error", error_code=type(exc).__name__, error=str(exc))
        logging.exception("Unexpected error: %s", phase)
    finally:
        row["ms"] = round((time.perf_counter() - started) * 1000, 3)
    return row, raw


def summarize(rows: list[dict]) -> dict:
    by_phase = {}
    for row in rows:
        k = row["phase"]
        by_phase.setdefault(k, []).append(row)
    return {
        k: {"count": len(v),
            "status": [x["status"] for x in v],
            "median_ms": round(statistics.median(x["ms"] for x in v), 3)}
        for k, v in by_phase.items() if v
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Проверка UID через прямое чтение блока 0 командой Cyb 0x6C"
    )
    parser.add_argument("--cards", type=int, choices=(1, 2), default=2,
                        help="Число разных карт для проверки (по умолчанию 2)")
    parser.add_argument("--timeout-ms", type=int, default=1500)
    args = parser.parse_args(argv)
    if not 1 <= args.timeout_ms <= 60000:
        parser.error("timeout-ms должен быть 1..60000")
    folder = Path(__file__).resolve().parents[1] / "diagnostics_logs"
    folder.mkdir(parents=True, exist_ok=True)
    stem = folder / ("cyb_6c_uid_" + datetime.now().strftime("%Y%m%d_%H%M%S_%f"))
    csv_path, json_path, log_path = (stem.with_suffix(ext)
                                     for ext in (".csv", ".json", ".log"))
    logging.basicConfig(filename=str(log_path), level=logging.WARNING,
                        encoding="utf-8", force=True)
    secret = secrets.token_bytes(32)
    report = {
        "library_version": r.__version__, "platform": platform.platform(),
        "settings": vars(args), "partial": True, "rows": [], "checks": {},
        "note": "Only anonymized fingerprints. Raw UID/card blocks never saved.",
    }
    reader_path = None

    def save_report():
        report["summary"] = summarize(report["rows"])
        tmp = json_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(json_path)

    with csv_path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()

        def save(row):
            report["rows"].append(row)
            writer.writerow({k: row.get(k) for k in FIELDS})
            f.flush()
            save_report()
            print(f"  {row['phase']}: {row['status']}; {row['ms']} мс"
                  + (f"; маска={row['mask']}" if row['mask'] is not None else "")
                  + (f"; UID совпал={row['uid_match']}" if row['uid_match'] is not None else ""))

        try:
            print("Закройте Master Manager, Cyb_Nfctool и другие программы, использующие Cyb.")
            print("Никаких команд записи: только 0x51, 0x6C, 0x69 (контроль).")
            print("Сначала проверим блок 0 напрямую ДО 0x69, потом сравним UID.")
            input("Переподключите Cyb к USB, приложите карту A и нажмите Enter: ")
            devices = [x for x in r.list_readers() if x.backend == "cyb"]
            if not devices:
                raise RuntimeError("Cyb не найден")
            for n, dev in enumerate(devices, 1):
                print(f"{n}: {dev.product} [{dev.vendor_id:04X}:{dev.product_id:04X}]")
            number = int(input("Выберите номер Cyb: ")) if len(devices) > 1 else 1
            if not 1 <= number <= len(devices):
                raise ValueError("Некорректный номер")
            reader_path = devices[number - 1].path
            with r._open_session(reader_path, args.timeout_ms) as session:
                if not isinstance(session, r._CybSession):
                    raise RuntimeError("Только Cyb")
                session.initialize()
                previous_uid_tag = None

                for label in ("A", "B")[:args.cards]:
                    if label == "B":
                        input("\nУберите A, приложите ДРУГУЮ карту B. Нажмите Enter: ")
                    print(f"\nКарта {label}:")
                    raw_block0 = None
                    raw_uid = None
                    result, reply0 = perform(
                        session, secret, label, f"{label}_direct_block0",
                        lambda: read(session, 0, 1), start=0, count=1)
                    save(result)
                    if result["status"] == "error":
                        raise RuntimeError("Ошибка обмена при чтении блока 0; остановлено")
                    parsed0 = decode_block(reply0, 0, 1)
                    if parsed0 is not None:
                        raw_block0 = parsed0[0]

                    ref, response = perform(
                        session, secret, label, f"{label}_reference_69",
                        session._poll)
                    save(ref)
                    if ref["status"] == "error":
                        raise RuntimeError("Контрольный UID через 0x69 не получен")
                    raw_uid, atqa, sak = response
                    if raw_block0 is not None:
                        result.update(compare_uid(raw_block0, raw_uid, secret))
                        # Update the in-memory row and rewrite report; CSV adds a separate check row below.
                        print(f"  UID из блока 0 совпадает с 0x69: "
                              f"{result['uid_match']}; UID длина={len(raw_uid)}; "
                              f"BCC4={result['bcc4_ok']}")
                    else:
                        print("  Блок 0 не прочитан; сравнение UID невозможно.")
                    check = {
                        "block0_before_69_ok": raw_block0 is not None,
                        "uid_length": len(raw_uid),
                        "uid_match": (raw_block0[:len(raw_uid)] == raw_uid
                                      if raw_block0 is not None else None),
                        "bcc4_ok": (compare_uid(raw_block0, raw_uid, secret)["bcc4_ok"]
                                    if raw_block0 is not None else None),
                        "uid_tag": tag(secret, raw_uid),
                        "original_block0_tag": tag(secret, raw_block0) if raw_block0 else None,
                    }
                    report["checks"][label] = check
                    save_report()

                    combined, combined_reply = perform(
                        session, secret, label, f"{label}_combined_0_1",
                        lambda: read(session, 0, 2), start=0, count=2)
                    save(combined)
                    if combined["status"] == "error":
                        raise RuntimeError("Ошибка обмена при одновременном чтении 0+1")
                    parsed2 = decode_block(combined_reply, 0, 2)
                    check["combined_mask"] = combined["mask"]
                    check["combined_status"] = combined["status"]
                    check["combined_uid_match"] = (
                        parsed2[0][:len(raw_uid)] == raw_uid if parsed2 else None)
                    check["combined_block0_match"] = (
                        parsed2[0] == raw_block0 if parsed2 and raw_block0 else None)
                    print(f"  Совместное чтение 0+1: {combined['status']}, "
                          f"маска={combined['mask']}, UID совпал={check['combined_uid_match']}")

                    block1, reply1 = perform(
                        session, secret, label, f"{label}_direct_block1",
                        lambda: read(session, 1, 1), start=1, count=1)
                    save(block1)
                    if block1["status"] == "error":
                        raise RuntimeError("Ошибка обмена при чтении блока 1")
                    p1 = decode_block(reply1, 1, 1)
                    check["combined_block1_match"] = (
                        parsed2[1] == p1[0] if parsed2 and p1 else None)
                    check["direct_block1_ok"] = p1 is not None
                    print(f"  Блок 1 отдельно совпал с совместным чтением: "
                          f"{check['combined_block1_match']}")
                    if previous_uid_tag is not None:
                        check["different_uid_from_previous"] = (
                            previous_uid_tag != check["uid_tag"])
                    previous_uid_tag = check["uid_tag"]
                    save_report()

                if args.cards == 2:
                    input("\nСнимите B и снова приложите A. Нажмите Enter: ")
                    row, reply = perform(
                        session, secret, "A_return", "A_return_direct_block0",
                        lambda: read(session, 0, 1), start=0, count=1)
                    save(row)
                    if row["status"] == "error":
                        raise RuntimeError("Ошибка обмена при возврате A")
                    parsed = decode_block(reply, 0, 1)
                    result = report["checks"]["A"]
                    result["return_block0_matches_A"] = (
                        tag(secret, parsed[0]) == result["original_block0_tag"]
                        if parsed else None)
                    save_report()

                report["partial"] = False
            print("\nСводка:")
            for label, check in report["checks"].items():
                print(label, check)
        except KeyboardInterrupt:
            report["interrupted"] = True
            print("\nПрервано пользователем; частичные данные сохранены.")
        except Exception as exc:
            report["fatal_error"] = str(exc)
            logging.exception("Диагностика UID через 6C")
            print("Ошибка диагностики:", exc)
        finally:
            if reader_path is not None:
                try:
                    report["cleanup_ok"] = r.close_readers(path=reader_path)
                except Exception as exc:
                    report["cleanup_ok"] = False
                    report["cleanup_error"] = str(exc)
                    logging.exception("Не удалось освободить Cyb")
            save_report()
            print("\nПришлите CSV и JSON:")
            print(csv_path)
            print(json_path)
            print("LOG при нормальной работе может быть пуст:", log_path)


if __name__ == "__main__":
    main()
