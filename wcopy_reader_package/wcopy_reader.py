"""Чтение и запись MIFARE Classic: блок 1, ключ A = FF FF FF FF FF FF.

Устройства: wCopy NSR109 / PMX-V624-C и Cyb_Nfctool (аппаратная проверка ожидается).
Пример: number = read_card_number()
Ошибки оборудования/протокола: RFIDError и его подклассы.
Неверные аргументы API: ValueError. См. README.md и PROTOCOL.md.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
import importlib
import logging
import threading
import time

__version__ = "1.5.2"
VID, PID = 0x2518, 0x6018
CYB_USB_IDS = ((0x0483, 0x4300), (0x0483, 0x4343))
BLOCK = 1
KEY_A = b"\xff" * 6
_LOCK = threading.Lock()
_LOG = logging.getLogger(__name__)
_LOG.addHandler(logging.NullHandler())


class RFIDError(Exception):
    """Общая ошибка. code/stage стабильны; status — сырой код, если он есть."""
    code = "RFID_ERROR"

    def __init__(self, message: str, *, stage: str,
                 status: int | None = None, response: bytes | None = None):
        super().__init__(message)
        self.stage = stage
        self.status = status
        self.response = response


class DependencyError(RFIDError):
    code = "DEPENDENCY_ERROR"


class ReaderNotFoundError(RFIDError):
    code = "READER_NOT_FOUND"


class MultipleReadersError(RFIDError):
    code = "MULTIPLE_READERS"


class ReaderOpenError(RFIDError):
    code = "READER_OPEN_ERROR"


class USBError(RFIDError):
    code = "USB_ERROR"


class ReaderTimeoutError(RFIDError):
    code = "READER_TIMEOUT"


class ProtocolError(RFIDError):
    code = "PROTOCOL_ERROR"


class ReaderCommandError(RFIDError):
    code = "READER_COMMAND_ERROR"


class NoCardError(RFIDError):
    code = "NO_CARD"


class UnsupportedCardError(RFIDError):
    code = "UNSUPPORTED_CARD"


class AuthenticationError(RFIDError):
    """Сбой этапа авторизации; не гарантирует, что причина именно в ключе."""
    code = "AUTHENTICATION_FAILED"


class CardReadError(RFIDError):
    code = "CARD_READ_FAILED"


class CardWriteError(RFIDError):
    code = "CARD_WRITE_FAILED"


class VerificationError(RFIDError):
    """После команды записи результат не подтверждён; карта могла измениться."""
    code = "VERIFICATION_FAILED"


class FeedbackError(RFIDError):
    """Сбой индикации считывателя; не отменяет уже прочитанные данные карты."""
    code = "FEEDBACK_FAILED"


@dataclass(frozen=True)
class ReaderInfo:
    path: bytes
    product: str
    manufacturer: str
    interface: int | None
    backend: str = "wcopy"
    vendor_id: int = VID
    product_id: int = PID


def _validate_format(offset: int, length: int, byteorder: str) -> None:
    if type(offset) is not int or type(length) is not int:
        raise ValueError("offset и length должны быть целыми числами")
    if offset < 0 or length < 1 or offset + length > 16:
        raise ValueError("Диапазон должен лежать внутри 16 байт блока")
    if byteorder not in ("big", "little"):
        raise ValueError("byteorder должен быть 'big' или 'little'")


@dataclass(frozen=True)
class CardData:
    uid: bytes
    block: bytes
    atqa: bytes
    sak: int

    def to_int(self, *, offset: int = 8, length: int = 8,
               byteorder: str = "big") -> int:
        """Беззнаковое двоичное число, не ASCII-строка и не MIFARE value block."""
        _validate_format(offset, length, byteorder)
        return int.from_bytes(self.block[offset:offset + length], byteorder, signed=False)

    @property
    def number(self) -> int:
        """Последние 8 байт блока как unsigned big-endian (uint64)."""
        return self.to_int()


def _get_hid():
    try:
        hid = importlib.import_module("hid")
    except (ImportError, OSError) as exc:
        raise DependencyError("Не удалось загрузить hidapi; установите requirements.txt",
                              stage="dependency") from exc
    if not hasattr(hid, "device") or not hasattr(hid, "enumerate"):
        raise DependencyError("Нужен пакет hidapi, импортируемый как hid",
                              stage="dependency")
    return hid


def _enumerate(hid) -> tuple[ReaderInfo, ...]:
    readers = []
    seen = set()
    try:
        for vid, pid in ((VID, PID), *CYB_USB_IDS):
            for device in hid.enumerate(vid, pid):
                path = device["path"]
                if path in seen:
                    continue
                if (vid, pid) == (VID, PID):
                    if device.get("interface_number") not in (0, -1, None):
                        continue
                    backend = "wcopy"
                else:
                    # Same descriptor checks as Cyb_Nfctool FindDevIsOk.
                    # ST's VID alone is not a sufficient device identification.
                    if not all(marker in (device.get(field) or "") for field, marker in (
                        ("manufacturer_string", "CYBDZKJ-BSJ"),
                        ("product_string", "TCC-TSY-TBY"),
                        ("serial_number", "BEGIN-2025"),
                    )):
                        continue
                    backend = "cyb"
                seen.add(path)
                readers.append(ReaderInfo(
                    path, device.get("product_string") or "",
                    device.get("manufacturer_string") or "", device.get("interface_number"),
                    backend, vid, pid))
    except OSError as exc:
        raise USBError("Ошибка перечисления HID-устройств", stage="enumerate") from exc
    return tuple(readers)


def list_readers() -> tuple[ReaderInfo, ...]:
    """Найти поддерживаемые wCopy и Cyb HID-считыватели; без отправки команд."""
    return _enumerate(_get_hid())


def _request(payload: bytes, sequence: int) -> bytes:
    if not 1 <= len(payload) <= 48:
        raise ValueError("Длина команды должна быть 1..48 байтов")
    report = bytearray([1, len(payload) + 6, sequence & 255, sequence >> 8])
    report.extend(payload)
    report.extend([~sum(report) & 255, 0xFE])
    return b"\0" + bytes(report).ljust(64, b"\0")


def _parse_report(raw: bytes, stage: str) -> tuple[int, bytes]:
    report = raw[1:] if len(raw) == 65 and raw[0] == 0 else raw
    if len(report) != 64 or report[0] != 2:
        raise ProtocolError("Некорректный размер/заголовок HID-ответа",
                            stage=stage, response=raw)
    size = report[1]
    if not 6 <= size <= 64 or report[size - 1] != 0xFD:
        raise ProtocolError("Некорректная длина/конец пакета", stage=stage, response=raw)
    if report[size - 2] != (~sum(report[:size - 2]) & 255):
        raise ProtocolError("Контрольная сумма ответа не совпала", stage=stage, response=raw)
    return int.from_bytes(report[2:4], "little"), report[4:size - 2]


def _fixed_body(body: bytes, size: int, stage: str) -> bytes:
    # Никогда не удаляем 90 00 из последних двух байтов самих данных блока.
    if len(body) == size:
        return body
    if len(body) == size + 2:
        if body[-2:] == b"\x90\0":
            return body[:-2]
        raise ReaderCommandError("Считыватель вернул ошибку статуса APDU",
                                 stage=stage, status=int.from_bytes(body[-2:], "big"),
                                 response=body)
    raise ProtocolError(f"Неожиданная длина ответа: {len(body)}, ожидается {size} или {size + 2}",
                        stage=stage, response=body)


class _Session:
    def __init__(self, device, timeout_ms: int):
        self.device = device
        self.timeout_ms = timeout_ms
        self.sequence = 0

    def exchange(self, payload: bytes, stage: str) -> bytes:
        sequence = self.sequence
        self.sequence = (sequence + 2) & 0xFFFF
        packet = _request(payload, sequence)
        _LOG.debug("%s TX %s", stage, packet.hex(" "))
        try:
            written = self.device.write(packet)
        except OSError as exc:
            raise USBError("Ошибка отправки команды по USB", stage=stage) from exc
        if written != len(packet):
            raise USBError(f"Неполная передача по USB: {written}/{len(packet)}", stage=stage)
        deadline = time.monotonic() + self.timeout_ms / 1000
        last = None
        for _ in range(20):
            remaining = int((deadline - time.monotonic()) * 1000)
            if remaining <= 0:
                break
            try:
                raw = bytes(self.device.read(65, remaining))
            except OSError as exc:
                raise USBError("Ошибка получения ответа по USB", stage=stage) from exc
            if not raw:
                break
            _LOG.debug("%s RX %s", stage, raw.hex(" "))
            received_sequence, data = _parse_report(raw, stage)
            if received_sequence == (sequence | 1):
                return data
            last = raw
        if last is not None:
            raise ProtocolError("Получены ответы с неподходящим номером запроса",
                                stage=stage, response=last)
        raise ReaderTimeoutError("Считыватель не ответил за отведённое время", stage=stage)

    def pn(self, command: bytes, stage: str) -> bytes:
        payload = b"\xff\0\0\0" + bytes([len(command) + 1, 0xD4]) + command
        data = self.exchange(payload, stage)
        if data[:2] != bytes([0xD5, command[0] + 1]):
            raise ProtocolError("Неожиданный ответ на PN-совместимую команду",
                                stage=stage, response=data)
        return data[2:]

    def configure(self, command: bytes, stage: str) -> None:
        _fixed_body(self.pn(command, stage), 0, stage)

    def initialize(self) -> None:
        init = self.exchange(bytes.fromhex("FF 00 9A 5A A5 54 69 61 6E"), "initialize")
        if init != b"\0":
            raise ReaderCommandError("Считыватель не подтвердил инициализацию",
                                     stage="initialize", response=init)

    def feedback_command(self, payload: bytes) -> bytes:
        body = self.exchange(payload, "feedback")
        # На проверенном wCopy ответ 90 01 не отражает реальный цвет LED.
        # Принимаем известные формы ответа, но не трактуем их как физическое состояние.
        if body == b"\0" or (len(body) == 2 and body[0] == 0x90 and body[1] <= 3):
            return body
        raise FeedbackError("Считыватель не подтвердил команду света/звука: " + body.hex(" "),
                            stage="feedback", response=body)

    def feedback(self, color: str, beep: bool, count: int = 1) -> tuple[bytes, ...]:
        replies = []
        if beep:
            replies.append(self.beep(count=count))
        replies.append(self.set_led(color))
        return tuple(replies)

    def beep(self, t: int = 5, count: int = 1) -> bytes:
        # Та же команда, которую формирует nfcPro_x64: FF 00 40 50 04 T 01 01 01.
        # T — значение поля команды, не миллисекунды. Цвет этим вызовом не задаём.
        _validate_beep_t(t)
        return self.feedback_command(bytes.fromhex("FF 00 40 50 04") + bytes([t, 1, 1, 1]))

    def set_led(self, color: str) -> bytes:
        control = {"off": 0x0C, "red": 0x0D, "green": 0x0E}[color]
        return self.feedback_command(bytes([0xFF, 0, 0x40, control, 4, 0, 0, 0, 0]))

    def read(self) -> CardData:
        self.initialize()
        # Сохраняем последовательность из успешного аппаратного теста.
        self.configure(bytes.fromhex("32 01 00"), "rf_off")
        time.sleep(0.05)
        self.configure(bytes.fromhex("32 01 01"), "rf_on")
        time.sleep(0.05)
        self.configure(bytes.fromhex("32 05 00 01 02"), "configure")
        body = self.pn(bytes.fromhex("4A 01 00"), "poll")
        # Наблюдение на NSR109-HIDIC V806N: без карты тело ответа D5 4B = 63 00.
        # Это firmware-specific трактовка результата поиска, не универсальный
        # смысл статуса 6300. Возможен также неуспешный поиск при наличии карты.
        if body == b"\x63\x00":
            raise NoCardError("Карта не обнаружена или поиск не удался (статус 63 00)",
                              stage="poll", status=0x6300, response=body)
        if body and body[0] == 0:
            _fixed_body(body, 1, "poll")
            raise NoCardError("Карта не обнаружена", stage="poll")
        if len(body) < 6 or body[0] != 1 or body[1] != 1:
            raise ProtocolError("Некорректный ответ поиска карты", stage="poll", response=body)
        sak, uid_size = body[4], body[5]
        if uid_size not in (4, 7):
            raise UnsupportedCardError("Неподдерживаемая длина UID", stage="poll", response=body)
        if len(body) < 6 + uid_size:
            raise ProtocolError("Неполный UID в ответе", stage="poll", response=body)
        if sak not in (0x08, 0x18, 0x09, 0x88):
            raise UnsupportedCardError(f"Неожиданный для Classic SAK=0x{sak:02X}",
                                       stage="poll", response=body)
        body = _fixed_body(body, 6 + uid_size, "poll")
        uid, atqa = body[6:], body[2:4]
        auth = bytes([0x40, 1, 0x60, BLOCK]) + KEY_A + uid[-4:]
        self.data_exchange(auth, 0, "authenticate", AuthenticationError)
        block = self.data_exchange(bytes([0x40, 1, 0x30, BLOCK]), 16, "read", CardReadError)
        return CardData(uid, block, atqa, sak)

    def data_exchange(self, command: bytes, size: int, stage: str, error_type) -> bytes:
        body = self.pn(command, stage)
        if not body:
            raise ProtocolError("В ответе отсутствует статус операции", stage=stage, response=body)
        if body[0] != 0:
            raise error_type(f"Операция {stage} завершилась со статусом 0x{body[0]:02X}",
                             stage=stage, status=body[0], response=body)
        return _fixed_body(body, size + 1, stage)[1:]


    def write_block(self, block: bytes) -> None:
        self.data_exchange(bytes([0x40, 1, 0xA0, BLOCK]) + block,
                           0, "write", CardWriteError)

    def write_number(self, encoded: bytes, offset: int, *, expected_uid=None, expected_block=None) -> CardData:
        before = self.read()
        if expected_uid is not None and before.uid != expected_uid:
            raise VerificationError("Карта заменена до записи; UID не совпал. Запись не выполнялась.",
                                    stage="prewrite", response=before.uid)
        if expected_block is not None and before.block != expected_block:
            raise VerificationError("Содержимое карты изменилось до записи. Запись не выполнялась.",
                                    stage="prewrite", response=before.block)
        expected = before.block[:offset] + encoded + before.block[offset + len(encoded):]
        # PN InDataExchange / MIFARE Write: один блок целиком, 16 байт.
        # Не повторяем запись автоматически при тайм-ауте/сбое.
        self.write_block(expected)
        try:
            # Новый RF-сеанс, поиск и авторизация: проверяем память карты,
            # а также UID, чтобы не принять другую карту за записанную.
            after = self.read()
        except RFIDError as exc:
            raise VerificationError(
                f"Команда записи выполнена, но обратное чтение не удалось: {exc}",
                stage="verify", status=exc.status, response=exc.response) from exc
        if after.uid != before.uid:
            raise VerificationError("При обратном чтении обнаружена другая карта (UID изменился)",
                                    stage="verify", response=after.uid)
        if after.block != expected:
            raise VerificationError("Обратное чтение не совпало с записанным блоком",
                                    stage="verify", response=after.block)
        return after


def _cyb_checksum(payload: bytes) -> bytes:
    # Manufacturer implementation uses an 8-bit length for XOR (even though
    # the frame's length field is 16-bit). Normal requests here are < 256 bytes.
    value = 0
    for byte in payload[:len(payload) & 255]:
        value ^= byte
    return bytes([value ^ 255, value])


def _cyb_request(command: int, payload: bytes) -> bytes:
    if len(payload) > 2041:
        raise ValueError("Слишком длинный пакет Cyb")
    return (b"\x55" + command.to_bytes(2, "big") + len(payload).to_bytes(2, "big")
            + payload + _cyb_checksum(payload))


class _CybSession(_Session):
    """Cyb_Nfctool native protocol. Static reverse engineering; hardware pending.

    Inherits the public write safety checks, not the wCopy USB framing.
    Only normal block access with known keys is used, never magic-card modes.
    """

    def __init__(self, device, timeout_ms: int):
        super().__init__(device, timeout_ms)
        self.host_control = False
        self.host_requested = False
        self.buffer = bytearray()

    def _drain(self, stage: str) -> None:
        self.buffer.clear()
        try:
            for _ in range(32):
                if not self.device.read(65, 1):
                    return
        except OSError as exc:
            raise USBError("Ошибка очистки входного потока Cyb", stage=stage) from exc
        raise ProtocolError("Непрерывный поток Cyb; закройте другие программы", stage=stage)

    def exchange_cyb(self, command: int, payload: bytes, stage: str) -> bytes:
        # No sequence IDs: discard old queued replies BEFORE the new request.
        # Never retry commands (especially writes) on timeout.
        self._drain(stage)
        packet = _cyb_request(command, payload)
        _LOG.debug("%s CYB TX %s", stage, packet.hex(" "))
        try:
            for start in range(0, len(packet), 64):
                report = b"\0" + packet[start:start + 64]
                written = self.device.write(report)
                _LOG.debug("%s CYB HID write requested=%d returned=%s report=%s",
                           stage, len(report), written, report.hex(" "))
                # Windows HIDAPI pads short writes to OutputReportByteLength
                # and returns that padded count. Cyb uses 64-byte reports + ID.
                # Keep the original short write; never resend an accepted command.
                if written not in (len(report), 65):
                    raise USBError(
                        f"Некорректная передача Cyb по USB: отправлено {written}, "
                        f"ожидалось {len(report)} или 65 с дополнением HIDAPI",
                        stage=stage)
        except OSError as exc:
            raise USBError("Ошибка отправки команды Cyb", stage=stage) from exc
        deadline = time.monotonic() + self.timeout_ms / 1000
        for _ in range(128):
            while self.buffer:
                # HID reports may be zero-padded; frame bytes are a stream.
                if self.buffer[0] == 0:
                    del self.buffer[0]
                    continue
                if self.buffer[0] != 0x55:
                    raise ProtocolError("Неизвестный заголовок Cyb", stage=stage,
                                        response=bytes(self.buffer))
                if len(self.buffer) < 5:
                    break
                size = int.from_bytes(self.buffer[3:5], "big")
                if size > 2041:
                    raise ProtocolError("Некорректная длина пакета Cyb", stage=stage,
                                        response=bytes(self.buffer))
                if len(self.buffer) < size + 7:
                    break
                frame = bytes(self.buffer[:size + 7])
                del self.buffer[:size + 7]
                body = frame[5:-2]
                if frame[-2:] != _cyb_checksum(body):
                    raise ProtocolError("Контрольная сумма Cyb не совпала", stage=stage,
                                        response=frame)
                if int.from_bytes(frame[1:3], "big") == command:
                    return body
                _LOG.debug("%s CYB unrelated frame %s", stage, frame.hex(" "))
            remaining = int((deadline - time.monotonic()) * 1000)
            if remaining <= 0:
                break
            try:
                raw = bytes(self.device.read(65, remaining))
            except OSError as exc:
                raise USBError("Ошибка получения ответа Cyb", stage=stage) from exc
            if not raw:
                break
            _LOG.debug("%s CYB RX %s", stage, raw.hex(" "))
            if len(raw) == 65 and raw[0] == 0:
                raw = raw[1:]
            self.buffer.extend(raw)
        if self.buffer.strip(b"\0"):
            raise ProtocolError("Неполный ответ Cyb", stage=stage, response=bytes(self.buffer))
        raise ReaderTimeoutError("Cyb не ответил за отведённое время", stage=stage)

    def initialize(self) -> None:
        if self.host_control:
            return
        self.host_requested = True
        body = self.exchange_cyb(0x51, b"\x01", "initialize")
        if body != b"\x01":
            raise ReaderCommandError("Cyb не подтвердил управление с ПК", stage="initialize",
                                     response=body)
        self.host_control = True

    def release(self) -> None:
        if not self.host_requested:
            return
        body = self.exchange_cyb(0x51, b"\0", "release")
        if body != b"\0":
            raise ReaderCommandError("Cyb не подтвердил автономный режим", stage="release",
                                     response=body)
        self.host_control = self.host_requested = False

    def _poll(self) -> tuple[bytes, bytes, int]:
        body = self.exchange_cyb(0x69, b"", "poll")
        # status, type, iso14a_card_select_t (17 bytes), optional ATS.
        if len(body) < 19:
            raise ProtocolError("Неполный ответ информации о карте Cyb", stage="poll", response=body)
        if body[0] == 0:
            raise NoCardError("Карта не обнаружена Cyb", stage="poll", response=body)
        size, sak = body[12], body[15]
        if size not in (4, 7) or sak not in (0x08, 0x18, 0x09, 0x88):
            raise UnsupportedCardError("Cyb: карта не поддерживается как MIFARE Classic",
                                       stage="poll", response=body)
        # Native ATQA is in ISO14443A wire order; retain the PN-style API order.
        return body[2:2 + size], body[13:15][::-1], sak

    @staticmethod
    def _block_parameters() -> bytes:
        # start block, count, normal access (0), key A, key B.
        # Both keys are supplied by this protocol; no key-search operation.
        return bytes([BLOCK, 1, 0]) + KEY_A + KEY_A

    def read(self) -> CardData:
        self.initialize()
        uid, atqa, sak = self._poll()
        body = self.exchange_cyb(0x6C, self._block_parameters(), "read")
        if len(body) != 20:
            raise ProtocolError("Ожидались маска результата и 16 байт блока Cyb",
                                stage="read", response=body)
        mask = int.from_bytes(body[:4], "big")
        if mask != 1:
            raise CardReadError("Cyb не прочитал блок 1; проверьте карту и ключ",
                                stage="read", status=mask, response=body)
        after_uid, after_atqa, after_sak = self._poll()
        if (after_uid, after_atqa, after_sak) != (uid, atqa, sak):
            raise VerificationError("Карта изменилась во время чтения Cyb",
                                    stage="read", response=after_uid)
        return CardData(uid, body[4:], atqa, sak)

    def write_block(self, block: bytes) -> None:
        body = self.exchange_cyb(0x6A, self._block_parameters() + block, "write")
        if len(body) != 4:
            raise ProtocolError("Некорректный ответ записи Cyb", stage="write", response=body)
        mask = int.from_bytes(body, "big")
        if mask != 1:
            raise CardWriteError("Cyb не подтвердил запись блока 1", stage="write",
                                 status=mask, response=body)

    def _send_feedback(self, payload: bytes) -> bytes:
        # CMD 55 has no acknowledgement. Do not wait or retry.
        report = b"\0" + _cyb_request(0x55, payload)
        _LOG.debug("feedback CYB TX %s", report.hex(" "))
        try:
            written = self.device.write(report)
        except OSError as exc:
            raise USBError("Ошибка отправки индикации Cyb", stage="feedback") from exc
        if written not in (len(report), 65):
            raise USBError("Неполная отправка индикации Cyb", stage="feedback")
        return b""

    def set_led(self, color: str) -> bytes:
        return self._send_feedback(bytes.fromhex(
            "00 00 00 00" if color == "off" else "00 01 01 00"))

    def beep(self, t: int = 5, count: int = 1) -> bytes:
        return self._send_feedback(bytes([1, max(1, t - 4), min(count, 255), 0]))

    def feedback(self, color: str, beep: bool, count: int = 1) -> tuple[bytes, ...]:
        # A later LED command can replace a running sound pattern.
        replies = [self.set_led(color)]
        if beep:
            replies.append(self.beep(count=count))
        return tuple(replies)


def read_card(*, path: bytes | None = None, timeout_ms: int = 2500) -> CardData:
    """Однократно прочитать блок 1 ключом A=FF…FF; открыть/закрыть USB автоматически.

    path — из list_readers(); при None требуется ровно одно устройство.
    timeout_ms — ожидание одного HID-ответа, НЕ срок всей функции.
    Карта должна уже лежать на считывателе. Повторный вызов снова читает карту.
    Функция блокирующая. Вызовы этого модуля сериализуются внутри процесса.
    """
    with _open_session(path, timeout_ms) as session:
        return session.read()


@contextmanager
def _open_session(path: bytes | None, timeout_ms: int, *, feedback: bool = False) -> Iterator[_Session | None]:
    if type(timeout_ms) is not int or not 1 <= timeout_ms <= 60000:
        raise ValueError("timeout_ms должен быть целым числом от 1 до 60000")
    if path is not None and (not isinstance(path, bytes) or not path):
        raise ValueError("path должен быть непустым bytes из list_readers() либо None")
    with _LOCK:
        hid = _get_hid()
        readers = _enumerate(hid)
        if path is not None:
            readers = tuple(r for r in readers if r.path == path)
        if not readers:
            raise ReaderNotFoundError("Поддерживаемый считыватель wCopy / Cyb не найден", stage="enumerate")
        if len(readers) != 1:
            raise MultipleReadersError("Найдено несколько считывателей; задайте path из list_readers()",
                                       stage="enumerate")
        device = None
        primary_error = None
        yielded = False
        quiet = feedback and readers[0].backend == "cyb"
        try:
            try:
                device = hid.device()
                device.open_path(readers[0].path)
            except OSError as exc:
                raise ReaderOpenError("Не удалось открыть HID-интерфейс; возможно, он занят или отключён",
                                      stage="open") from exc
            session = (_CybSession if readers[0].backend == "cyb" else _Session)(device, timeout_ms)
            try:
                yielded = True
                yield session
            finally:
                # Preserve the primary error if releasing host control also fails.
                import sys
                active_error = sys.exception()
                if isinstance(session, _CybSession):
                    try:
                        session.release()
                    except RFIDError as exc:
                        if active_error is None:
                            raise
                        active_error.add_note(f"Не удалось вернуть автономный режим Cyb: {exc}")
        except BaseException as exc:
            primary_error = exc
            if quiet and isinstance(exc, RFIDError):
                _LOG.warning("Ошибка индикации Cyb: %s", exc)
                if not yielded:
                    yield None
            else:
                raise
        finally:
            if device is not None:
                try:
                    device.close()
                except OSError as exc:
                    if quiet:
                        _LOG.warning("Ошибка закрытия HID после индикации Cyb: %s", exc)
                    elif primary_error is None:
                        raise USBError("Ошибка закрытия HID-интерфейса", stage="close") from exc
                    elif primary_error is not None:
                        primary_error.add_note(f"Дополнительно не удалось закрыть HID: {exc}")


def read_card_number(*, path: bytes | None = None, timeout_ms: int = 2500,
                     offset: int = 8, length: int = 8, byteorder: str = "big") -> int:
    """Вернуть беззнаковое число из блока 1. При ошибке поднять RFIDError.

    По умолчанию: последние 8 байт, big-endian (uint64). Ноль — корректное значение карты.
    Например, последние 4 байта: offset=12, length=4.
    Формат задаёт записывающее приложение; автоматически он не определяется.
    """
    _validate_format(offset, length, byteorder)
    return read_card(path=path, timeout_ms=timeout_ms).to_int(
        offset=offset, length=length, byteorder=byteorder)


def write_card_number(number: int, *, path: bytes | None = None,
                      timeout_ms: int = 2500, offset: int = 8,
                      length: int = 8, byteorder: str = "big",
                      expected_uid: bytes | None = None,
                      expected_block: bytes | None = None) -> int:
    """Записать ID в блок 1 ключом A=FF…FF и обязательно проверить чтением.

    По умолчанию меняются байты 8..15 (uint64 big-endian); остальные сохраняются.
    Возвращает число, фактически прочитанное после записи, только при совпадении
    всего блока и UID. Карта должна лежать на считывателе до завершения.
    RFIDError означает, что успех НЕ подтверждён; после команды write данные
    уже могли измениться. Автоматических повторов записи нет.
    Формат и диапазон проверяются до обращения к оборудованию.
    expected_uid / expected_block: при передаче сравниваются с начальным чтением
    в том же сеансе ДО команды записи. Несовпадение: VerificationError(stage="prewrite").
    """
    _validate_format(offset, length, byteorder)
    if type(number) is not int or not 0 <= number < (1 << (8 * length)):
        raise ValueError(f"number должен быть целым числом от 0 до {(1 << (8 * length)) - 1}")
    if expected_uid is not None and (not isinstance(expected_uid, bytes) or len(expected_uid) not in (4, 7)):
        raise ValueError("expected_uid должен быть bytes длиной 4 или 7 либо None")
    if expected_block is not None and (not isinstance(expected_block, bytes) or len(expected_block) != 16):
        raise ValueError("expected_block должен быть bytes длиной 16 либо None")
    encoded = number.to_bytes(length, byteorder, signed=False)
    with _open_session(path, timeout_ms) as session:
        return session.write_number(encoded, offset, expected_uid=expected_uid,
                                    expected_block=expected_block).to_int(
            offset=offset, length=length, byteorder=byteorder)


def set_led(color: str, *, path: bytes | None = None, timeout_ms: int = 2500,
            initialize: bool = False) -> bytes:
    """Послать команду индикации red/green/off; вернуть сырой ответ.

    Cyb: red и green отправляют 00 01 01 00 (включить красный LED без
    звука), off — 00 00 00 00. Другие цвета аппаратно не подтверждены.
    Ответа нет: возвращается b"". Ошибки USB/инициализации/закрытия для
    выбранного Cyb только журналируются. Ошибки аргументов и выбора
    устройства сохраняются. По умолчанию управление с ПК не включается.

    На NSR109-HIDIC V806N прямое задание цвета этими масками не подтверждено:
    red/green/off ведут себя одинаково. Однако вызов после КАЖДОГО опроса,
    включая «нет карты», нужен в проверенной схеме для штатного красного/
    зелёного LED и писка прошивки. Сохраняйте вызовы, как в watch_example.
    off также не гарантирует выключение LED. Ответ 90 01 не доказывает цвет.
    Самостоятельный вызов после записи не дал видимого переключения.
    Отдельной команды писка здесь нет; штатный звук может возникнуть сам.
    initialize=True добавляет INIT перед командой; обычно после read/write
    используется False. Память карты не читается и не записывается.
    """
    if color not in ("red", "green", "off"):
        raise ValueError("color должен быть red, green или off")
    if type(initialize) is not bool:
        raise ValueError("initialize должен быть bool")
    with _open_session(path, timeout_ms, feedback=True) as session:
        if session is None:
            return b""
        if initialize:
            session.initialize()
        return session.set_led(color)
    return b""


def _validate_beep_count(count: int) -> None:
    if type(count) is not int or count <= 0:
        raise ValueError("count должен быть целым числом больше нуля")


def _validate_beep_t(t: int) -> None:
    if type(t) is not int or not 1 <= t <= 255:
        raise ValueError("t должен быть целым числом от 1 до 255 (поле T, не миллисекунды)")


def beep(*, t: int = 5, count: int = 1, path: bytes | None = None, timeout_ms: int = 2500,
         initialize: bool = False) -> bytes:
    """Подать звуковой сигнал (на Cyb — count сигналов).

    count — положительное целое, по умолчанию 1. Старый wCopy всегда
    подаёт один сигнал независимо от count. Cyb использует min(count, 255).
    Cyb: команда 01 B C 00, B=max(1, t-4), C=количество сигналов.
    Таким образом t=1..5 даёт B=01, t=6 — 02, t=7 — 03.
    Писк также меняет LED. Ответа нет: возвращается b"". Ошибки связи
    с выбранным Cyb журналируются, не передаются приложению; ошибки
    аргументов и выбора устройства сохраняются. По умолчанию без захвата ПК.

    Для старого wCopy t — сырое поле T (целое 1..255), НЕ миллисекунды. По умолчанию 5,
    как в обычных вызовах nfcPro. Аппаратно проверены T=1,3,5,10; увеличение
    удлиняет писк. T=10 используется в write_example после проверки записи.
    Для больших T может потребоваться увеличить timeout_ms (например, 5000).
    Недопустимое t вызывает ValueError до обращения к USB.
    initialize=True выполняет INIT; после read/write он обычно не требуется.
    Не посылает команду установки цвета и не обращается к памяти карты.
    """
    _validate_beep_t(t)
    _validate_beep_count(count)
    if type(initialize) is not bool:
        raise ValueError("initialize должен быть bool")
    with _open_session(path, timeout_ms, feedback=True) as session:
        if session is None:
            return b""
        if initialize:
            session.initialize()
        return session.beep(t, count=count)
    return b""


def set_reader_feedback(color: str, *, beep: bool = False, count: int = 1, path: bytes | None = None,
                        timeout_ms: int = 2500, initialize: bool = False) -> tuple[bytes, ...]:
    """Совместимый комбинированный вызов команд индикации.

    Cyb: red/green включают красный LED командой 00 01 01 00,
    off выключает его командой 00 00 00 00. При beep=True после LED
    отправляется 01 01 C 00; звук может снова включить LED даже при off.
    Такой порядок предотвращает отмену звука следующей командой LED.
    count — положительное целое, по умолчанию 1; Cyb ограничивает его 255,
    старый wCopy всегда использует 1. Возврат Cyb: (b"",) или (b"", b"").
    Ошибки связи с выбранным Cyb журналируются; при сбое отправки/инициализации
    возврат (). Сбой закрытия не меняет уже полученный результат.
    Ошибки аргументов и выбора устройства сохраняются.

    Для wCopy color: red/green/off с ограничениями set_led (цвет не подтверждён).
    beep=True использует T=5. Для другого T используйте отдельный beep(t=...).
    Возвращает ответы устройства: подтверждение команды не доказывает цвет/звук.
    initialize=True для самостоятельного теста, False после чтения в watch.
    Не отправляет команд чтения/записи памяти карты.
    """
    if color not in ("red", "green", "off"):
        raise ValueError("color должен быть red, green или off")
    _validate_beep_count(count)
    if type(beep) is not bool or type(initialize) is not bool:
        raise ValueError("beep и initialize должны быть bool")
    with _open_session(path, timeout_ms, feedback=True) as session:
        if session is None:
            return ()
        if initialize:
            session.initialize()
        return session.feedback(color, beep, count=count)
    return ()


@dataclass(frozen=True)
class CardPresented:
    """Новая успешно прочитанная карта. number — uint64, uid — байты UID."""
    card: CardData

    @property
    def number(self) -> int:
        return self.card.number

    @property
    def uid(self) -> bytes:
        return self.card.uid


@dataclass(frozen=True)
class CardError:
    """Ошибка чтения/подключения во время наблюдения."""
    error: RFIDError


@dataclass(frozen=True)
class CardState:
    """Состояние после каждого успешного опроса или ответа «нет карты».

    present учитывает removal_checks. is_new=True только при новом успешном
    чтении; затем отдельно выдаётся CardPresented с данными. Ошибки USB и
    авторизации не превращаются в CardState(False). Включается report_state=True.
    """
    present: bool
    is_new: bool = False


def watch_cards(*, stop: threading.Event | None = None,
                interval: float = 0.25, removal_checks: int = 2,
                path: bytes | None = None, timeout_ms: int = 2500,
                feedback: bool = False, sound: bool = True,
                report_state: bool = False) -> Iterator[CardPresented | CardError | CardState]:
    """Блокирующий генератор CardPresented / CardError; см. README.

    Событие карты — только после успешного чтения. Повторы одного UID подавляются
    до removal_checks последовательных ответов «нет карты» или другого UID.
    USB-сбой, тайм-аут и ошибка ключа НЕ считаются снятием карты.
    stop.set() завершает цикл после текущей операции. Запускать в рабочем потоке.
    Исключения вызывающего кода не перехватываются.
    feedback=True: команды для штатной индикации прошивки (не прямого цвета).
    Ошибка индикации выдаётся отдельно и отключает индикацию до перезапуска
    генератора; чтение продолжается. Удерживаемая карта повторно не пищит.
    sound=False отключает только нашу команду писка, сохраняя команды LED.
    На самостоятельные звуки прошивки этот параметр не влияет.
    report_state=True добавляет CardState на каждом опросе для индикации
    в приложении. По умолчанию команд LED/звука нет. feedback/sound сохранены
    для совместимости; новым приложениям лучше вызывать set_led/beep самим.
    """
    import math
    if not isinstance(interval, (int, float)) or not math.isfinite(interval) or interval <= 0:
        raise ValueError("interval должен быть положительным конечным числом секунд")
    if type(removal_checks) is not int or removal_checks < 1:
        raise ValueError("removal_checks должен быть целым числом >= 1")
    if type(timeout_ms) is not int or not 1 <= timeout_ms <= 60000:
        raise ValueError("timeout_ms должен быть целым числом от 1 до 60000")
    if path is not None and (not isinstance(path, bytes) or not path):
        raise ValueError("path должен быть непустым bytes либо None")
    if type(feedback) is not bool:
        raise ValueError("feedback должен быть bool")
    if type(sound) is not bool:
        raise ValueError("sound должен быть bool")
    if type(report_state) is not bool:
        raise ValueError("report_state должен быть bool")
    stop = stop if stop is not None else threading.Event()
    last_uid = None
    absent = 0
    last_error = None
    feedback_enabled = feedback

    def update_feedback(color, beep=False):
        nonlocal feedback_enabled
        if not feedback_enabled:
            return None
        try:
            set_reader_feedback(color, beep=beep, path=path, timeout_ms=timeout_ms)
        except RFIDError as error:
            feedback_enabled = False
            failure = FeedbackError(
                f"Индикация отключена до перезапуска наблюдения: {error}",
                stage="feedback", status=error.status, response=error.response)
            failure.__cause__ = error
            return CardError(failure)
        return None

    while not stop.is_set():
        try:
            card = read_card(path=path, timeout_ms=timeout_ms)
        except NoCardError:
            absent += 1
            last_error = None
            if absent >= removal_checks:
                last_uid = None
            warning = update_feedback("green" if last_uid is not None else "red")
            if report_state:
                yield CardState(last_uid is not None)
            if warning is not None:
                yield warning
        except RFIDError as error:
            absent = 0
            signature = (error.code, error.stage, error.status)
            if signature != last_error:
                last_error = signature
                yield CardError(error)
            # USB/ошибки поиска не доказывают наличие рабочего канала управления.
            # Не создаём повторные задержки дополнительными запросами при сбоях.
        else:
            absent = 0
            last_error = None
            is_new = card.uid != last_uid
            warning = update_feedback("green", beep=is_new and sound)
            if report_state:
                yield CardState(True, is_new)
            if is_new:
                last_uid = card.uid
                yield CardPresented(card)
            if warning is not None:
                yield warning
        if stop.wait(interval):
            break
