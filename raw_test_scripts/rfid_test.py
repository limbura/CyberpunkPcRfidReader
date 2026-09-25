#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Консольный тест PMX-V624-C / wCopy, USB VID=2518 PID=6018.

Windows, Python 3.13, пакет pip: hidapi (импортируется как hid).
Запуск: python rfid_test.py
Только поиск устройства: python rfid_test.py --list
Выбор строки из списка: python rfid_test.py --index 0

Тест посылает три команды: инициализацию, запрос модели, запрос номера.
Команд чтения/записи карты здесь нет. Для этого теста карта не нужна.
На физическом PMX-V624-C этот скрипт пока не проверен.

Основание: статический разбор предоставленного nfcPro_x64.exe:
  0x14004a5d0 — поиск USB, включая 2518:6018;
  0x1400453f0 — упаковка команд, 0x140043c00 — инициализация;
  0x140045750 — запросы модели и серийного номера.
Описание ответов родственного X7 с PID=6022:
https://github.com/TenorGroup/tenor-rekey/blob/main/PROTOCOL.md
Сверка с реальным ответом PID=6018 — цель этого теста.
"""

import argparse
from datetime import datetime
from importlib.metadata import PackageNotFoundError, version
import logging
from pathlib import Path
import platform
import sys
import time


VID = 0x2518
PID = 0x6018
TIMEOUT_MS = 2500
log = logging.getLogger("rfid_test")


def setup_log():
    """Вывод в окно терминала и в текстовый файл рядом со скриптом."""
    log.setLevel(logging.INFO)
    log.propagate = False
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(logging.Formatter("%(message)s"))
    log.addHandler(console)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    path = Path(__file__).resolve().with_name(f"rfid_test_log_{stamp}.txt")
    try:
        file_handler = logging.FileHandler(path, mode="x", encoding="utf-8")
    except OSError as exc:
        log.info("Лог будет только в терминале: %s", exc)
        return
    file_handler.setFormatter(logging.Formatter("%(message)s"))
    log.addHandler(file_handler)
    log.info("Файл с результатом: %s", path.name)


def make_request(payload, sequence):
    """Нулевой Report ID + 64 байта HID-отчёта."""
    if not 1 <= len(payload) <= 48:
        raise ValueError("Длина команды должна быть от 1 до 48 байтов")
    report = bytearray([0x01, len(payload) + 6,
                        sequence & 0xFF, (sequence >> 8) & 0xFF])
    report.extend(payload)
    report.append((~sum(report)) & 0xFF)
    report.append(0xFE)
    return b"\x00" + bytes(report).ljust(64, b"\x00")


def parse_response(raw):
    """Проверить оболочку ответа и вернуть (номер, данные)."""
    report = bytes(raw)
    # Обычно HIDAPI уже убирает нулевой Report ID у входящих данных.
    if len(report) == 65 and report[0] == 0:
        report = report[1:]
    if len(report) < 6 or report[0] != 0x02:
        raise ValueError("неизвестный заголовок ответа")
    total = report[1]
    if not 6 <= total <= min(64, len(report)):
        raise ValueError(f"неожиданная длина пакета: {total}")
    if report[total - 1] != 0xFD:
        raise ValueError("неожиданный завершающий байт")
    checksum = (~sum(report[:total - 2])) & 0xFF
    if report[total - 2] != checksum:
        raise ValueError("контрольная сумма не совпала")
    sequence = int.from_bytes(report[2:4], "little")
    return sequence, report[4:total - 2]


def exchange(device, title, payload, sequence):
    """Один запрос; сохраняем сырые ответы даже при незнакомом формате."""
    packet = make_request(payload, sequence)
    log.info("\n%s | команда: %s", title, payload.hex(" ").upper())
    log.info("TX (%d байт): %s", len(packet), packet.hex(" ").upper())
    written = device.write(packet)
    log.info("HIDAPI передала байтов: %s", written)
    if written != len(packet):
        raise OSError(f"Неполная передача: {written} из {len(packet)} байтов")

    deadline = time.monotonic() + TIMEOUT_MS / 1000
    received = False
    # Ограничение и по времени, и по числу пакетов.
    for _ in range(20):
        left_ms = int((deadline - time.monotonic()) * 1000)
        if left_ms <= 0:
            break
        raw = bytes(device.read(65, left_ms))
        if not raw:
            break
        received = True
        log.info("RX (%d байт): %s", len(raw), raw.hex(" ").upper())
        try:
            reply_sequence, data = parse_response(raw)
        except ValueError as exc:
            log.info("Ответ получен, но его формат не подтверждён: %s", exc)
            continue
        if reply_sequence != (sequence | 1):
            log.info("Номер ответа %d, ожидается %d; ждём следующий пакет.",
                     reply_sequence, sequence | 1)
            continue
        log.info("Ответ прошёл проверку; данные: %s", data.hex(" ").upper())
        return data
    if received:
        log.info("Подходящий ответ не распознан. Сырые байты сохранены в логе.")
    else:
        log.info("Ответ не получен за %.1f секунды.", TIMEOUT_MS / 1000)
    return None


def read_text(data):
    """Однобайтовый статус не выдаём за строку модели/серийного номера."""
    if data is None:
        return None
    text = data.rstrip(b"\x00")
    if len(text) < 2 or any(c < 32 or c > 126 for c in text):
        return None
    return text.decode("ascii")


def main():
    parser = argparse.ArgumentParser(description="Тест HID-считывателя 2518:6018")
    parser.add_argument("--list", action="store_true", help="только список устройств")
    parser.add_argument("--index", type=int, help="номер строки из списка, начиная с 0")
    args = parser.parse_args()
    setup_log()
    log.info("Тест PMX-V624-C / wCopy | VID=2518 PID=6018")
    log.info("Python %s | %s", platform.python_version(), platform.system())
    try:
        import hid
    except ImportError as exc:
        log.info("Не удалось загрузить библиотеку hidapi: %s", exc)
        log.info('Установи её тем же Python: "%s" -m pip install hidapi', sys.executable)
        return 1
    if not hasattr(hid, "device") or not hasattr(hid, "enumerate"):
        log.info("Загрузился другой модуль hid: %s", getattr(hid, "__file__", "?"))
        log.info("Нужен пакет hidapi. Используй отдельную .venv по инструкции.")
        return 1
    try:
        log.info("Пакет hidapi: %s", version("hidapi"))
    except PackageNotFoundError:
        pass

    devices = hid.enumerate(VID, PID)
    log.info("\nНайдено HID-интерфейсов: %d", len(devices))
    for i, info in enumerate(devices):
        log.info("[%d] USB-название: %r; производитель: %r", i,
                 info.get("product_string"), info.get("manufacturer_string"))
        log.info("    interface=%s; usage_page=%s; usage=%s",
                 info.get("interface_number"), info.get("usage_page"), info.get("usage"))
        log.info("    path=%r", info.get("path"))
    if not devices:
        log.info("Считыватель 2518:6018 не найден. Проверь USB-подключение.")
        return 2
    if args.list:
        return 0

    # При нескольких совпадениях не выбираем случайное устройство.
    index = args.index
    if index is None:
        if len(devices) != 1:
            log.info("Несколько совпадений. Пришли лог или выбери строку: --index N")
            return 2
        index = 0
    if not 0 <= index < len(devices):
        log.info("Такого индекса нет. Допустимо: 0 .. %d", len(devices) - 1)
        return 2

    device = hid.device()
    try:
        device.open_path(devices[index]["path"])
        log.info("\nHID-интерфейс [%d] открыт.", index)
        # В nfcPro результат INIT не блокирует последующие запросы.
        init = exchange(device, "Инициализация",
                        bytes.fromhex("FF 00 9A 5A A5 54 69 61 6E"), 0)
        model_data = exchange(device, "Запрос модели", bytes.fromhex("FF 00 68"), 2)
        serial_data = exchange(device, "Запрос серийного номера", bytes.fromhex("FF 00 69"), 4)
    finally:
        device.close()
        log.info("\nHID-интерфейс закрыт.")

    model = read_text(model_data)
    serial = read_text(serial_data)
    log.info("\nМодель: %s", model or "строка не получена; смотри RX")
    log.info("Серийный номер: %s", serial or "строка не получена; смотри RX")
    if model or serial:
        log.info("УСПЕХ: считыватель ответил на запрос информации из Python.")
        log.info("Чтение памяти карты этим тестом ещё не проверялось.")
        return 0
    if any(data is not None for data in (init, model_data, serial_data)):
        log.info("Обмен пакетами подтверждён, но модель/номер не распознаны.")
    else:
        log.info("Ожидаемый протокол пока не подтверждён. Пришли весь лог.")
    return 3


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log.info("\nТест остановлен пользователем.")
        sys.exit(130)
    except OSError as exc:
        log.info("\nОшибка доступа/обмена с USB: %s", exc)
        log.info("Закрой nfcPro, переподключи считыватель и повтори тест.")
        sys.exit(1)
