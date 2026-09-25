#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""Чтение блока 1, сектор 0, MIFARE Classic, ключ FF FF FF FF FF FF.

Положить рядом с rfid_test.py из первого, успешно выполненного теста.
Запуск: .\.venv\Scripts\python.exe .\rfid_read_block1.py
По умолчанию ключ A; явно выбрать B: добавить --key-type B.

Основание: предоставленный nfcPro_x64.exe (статический анализ):
  0x14004a6c0: FF 00 00 00 Lc D4 <command>, ответ D5 <command+1>;
  0x14004afb0: RFConfiguration 32 01 00/01, 32 05 00 01 02;
  0x14004bda0 и константа 0x14008ef90: InListPassiveTarget 4A 01 00;
  0x14004b140: InDataExchange 40 01 <card command>;
  0x140041c30: MIFARE 60/61 + block + 10 bytes (key and UID);
  0x140041dc9: ответ чтения: status=00 + 16 bytes + 90 00.
Также: NXP AN10682, раздел MIFARE Classic, страницы 38–42:
https://www.nxp.com/docs/en/nxp/application-notes/AN10682.pdf

Новый путь команд чтения ещё требует проверки на физическом считывателе.
Скрипт не содержит команд записи в карту или смены ключей.
"""

import argparse
import sys
import time

try:
    import rfid_test as transport
except ImportError:
    print("Рядом с этим файлом должен лежать rfid_test.py из первого теста.")
    raise SystemExit(1)


BLOCK = 1
KEY = bytes.fromhex("FF FF FF FF FF FF")
log = transport.log


class TestError(Exception):
    pass


def wrapped_command(command):
    """PN-совместимая команда внутри фирменного HID-протокола."""
    if not command or len(command) > 42:
        raise ValueError("Недопустимая длина команды")
    return bytes.fromhex("FF 00 00 00") + bytes([len(command) + 1, 0xD4]) + command


def expected_length(body, size, title):
    """Допускаем служебные 90 00 только сверх ожидаемой длины данных.

    Это сохраняет последние байты блока, даже если сам блок кончается 90 00.
    """
    if len(body) == size:
        return body
    if len(body) == size + 2 and body[-2:] == b"\x90\x00":
        return body[:-2]
    raise TestError(f"{title}: неожиданный размер или статус ответа: {body.hex(' ').upper()}")


class Reader:
    def __init__(self, device):
        self.device = device
        self.sequence = 0

    def exchange(self, title, payload):
        sequence = self.sequence
        self.sequence = (sequence + 2) & 0xFFFF
        reply = transport.exchange(self.device, title, payload, sequence)
        if reply is None:
            raise TestError(f"{title}: нет подходящего ответа. Дальнейшие команды остановлены.")
        return reply

    def pn(self, title, command):
        reply = self.exchange(title, wrapped_command(command))
        header = bytes([0xD5, (command[0] + 1) & 0xFF])
        if not reply.startswith(header):
            raise TestError(
                f"{title}: ожидался заголовок {header.hex(' ').upper()}, "
                f"получено {reply.hex(' ').upper()}. Нужен разбор лога.")
        return reply[2:]

    def configure(self, title, command):
        expected_length(self.pn(title, command), 0, title)


def parse_target(body):
    if not body:
        raise TestError("Пустой ответ поиска карты")
    if body[0] == 0:
        expected_length(body, 1, "Поиск карты")
        raise TestError("Карта не обнаружена. Положи её на считыватель и повтори запуск.")
    if body[0] != 1 or len(body) < 6:
        raise TestError("Неожиданный ответ поиска карты; смотри RX в логе.")
    target, atqa, sak, uid_length = body[1], body[2:4], body[4], body[5]
    if target != 1 or uid_length not in (4, 7):
        raise TestError(f"Неожиданные параметры карты: target={target}, UID length={uid_length}")
    if len(body) < 6 + uid_length:
        raise TestError("Ответ содержит неполный UID")
    uid = body[6:6 + uid_length]
    log.info("\nUID карты: %s", uid.hex(" ").upper())
    log.info("ATQA: %s | SAK: %02X", atqa.hex(" ").upper(), sak)
    if sak not in (0x08, 0x18, 0x09, 0x88):
        raise TestError(f"SAK={sak:02X} не соответствует ожидаемому Classic. Пришли лог.")
    expected_length(body, 6 + uid_length, "Данные карты")
    return target, uid


def checked_data_exchange(body, size, title):
    if not body:
        raise TestError(f"{title}: отсутствует статус операции")
    if body[0] != 0:
        raise TestError(
            f"{title}: статус 0x{body[0]:02X}; "
            "возможны несовпадение ключа, ограничения доступа или потеря связи с картой. "
            "Точная причина по одному статусу не установлена.")
    return expected_length(body, size + 1, title)[1:]


def read_block1(device, key_type="A"):
    if key_type not in ("A", "B"):
        raise ValueError("Тип ключа должен быть A или B")
    reader = Reader(device)
    init = reader.exchange("Инициализация", bytes.fromhex("FF 00 9A 5A A5 54 69 61 6E"))
    if init != b"\x00":
        raise TestError(f"Неожиданный ответ инициализации: {init.hex(' ')}")

    # Перезапускаем радиополе, чтобы убрать состояние предыдущего сеанса.
    reader.configure("Выключение радиополя", bytes.fromhex("32 01 00"))
    time.sleep(0.05)
    reader.configure("Включение радиополя", bytes.fromhex("32 01 01"))
    time.sleep(0.05)
    # Те же конечные повторы поиска, что в функции инициализации nfcPro.
    reader.configure("Настройка повторов поиска", bytes.fromhex("32 05 00 01 02"))
    target, uid = parse_target(reader.pn("Поиск карты ISO14443A", bytes.fromhex("4A 01 00")))

    # В MIFARE-аутентификацию передаются последние 4 байта UID.
    auth = bytes([0x40, target, 0x60 if key_type == "A" else 0x61, BLOCK]) + KEY + uid[-4:]
    checked_data_exchange(reader.pn(f"Авторизация блока 1, ключ {key_type}", auth),
                          0, "Авторизация")
    log.info("Авторизация успешна.")

    command = bytes([0x40, target, 0x30, BLOCK])
    block = checked_data_exchange(reader.pn("Чтение блока 1", command), 16, "Чтение")
    log.info("\nУСПЕХ: прочитано 16 байт блока 1 (сектор 0).")
    log.info("Блок 1 HEX: %s", block.hex(" ").upper())
    log.info("Блок 1 ASCII: %s", "".join(chr(b) if 32 <= b <= 126 else "." for b in block))
    log.info("Точки в ASCII обозначают непечатные байты. Точное содержимое — строка HEX.")
    return block


def main():
    parser = argparse.ArgumentParser(description="Прочитать блок 1 с ключом FF FF FF FF FF FF")
    parser.add_argument("--key-type", choices=("A", "B"), default="A")
    parser.add_argument("--index", type=int, help="индекс HID-интерфейса при нескольких совпадениях")
    args = parser.parse_args()
    transport.setup_log()
    log.info("Тест чтения блока 1 | VID=2518 PID=6018 | ключ %s = FF FF FF FF FF FF", args.key_type)
    log.info("Python %s", sys.version.split()[0])
    try:
        import hid
    except ImportError as exc:
        raise TestError(f"Библиотека hidapi не загрузилась: {exc}. Запусти через прежнюю .venv.")
    if not hasattr(hid, "device"):
        raise TestError("Загружена другая библиотека hid. Запусти через прежнюю .venv.")
    devices = hid.enumerate(transport.VID, transport.PID)
    for i, info in enumerate(devices):
        log.info("[%d] %s | interface=%s | path=%r", i, info.get("product_string"),
                 info.get("interface_number"), info.get("path"))
    if not devices:
        raise TestError("Считыватель не найден. Проверь USB-подключение.")
    index = args.index
    if index is None:
        if len(devices) != 1:
            raise TestError("Найдено несколько интерфейсов. Пришли лог или укажи --index N.")
        index = 0
    if not 0 <= index < len(devices):
        raise TestError("Указан несуществующий индекс интерфейса")

    log.info("\nПоложи ОДНУ карту на считыватель и не убирай её до конца теста.")
    log.info("Нажми Enter, чтобы начать чтение (nfcPro должна быть закрыта).")
    input()
    device = hid.device()
    try:
        device.open_path(devices[index]["path"])
        log.info("HID-интерфейс открыт.")
        read_block1(device, args.key_type)
    finally:
        device.close()
        log.info("HID-интерфейс закрыт.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (TestError, OSError, EOFError) as exc:
        log.error("\nТест остановлен: %s", exc)
        log.error("Пришли весь файл лога. Перед повторным запуском при необходимости переподключи USB.")
        sys.exit(1)
    except KeyboardInterrupt:
        log.info("\nТест остановлен пользователем.")
        sys.exit(130)
