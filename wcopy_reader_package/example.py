"""Консольный пример: python example.py [--debug]."""
import argparse
import logging
from wcopy_reader import (
    read_card_number, NoCardError, AuthenticationError, CardReadError,
    ReaderNotFoundError, ReaderOpenError, ReaderTimeoutError, USBError, RFIDError,
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", action="store_true", help="показывать USB-пакеты")
    args = parser.parse_args()
    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(message)s")
    input("Закройте nfcPro, положите одну карту на считыватель и нажмите Enter: ")
    try:
        number = read_card_number()
    except NoCardError:
        print("Карта не обнаружена. Приложите карту и повторите запуск.")
    except AuthenticationError as exc:
        print(f"Авторизация не прошла (статус {exc.status:#04x}). "
              "Проверьте ключ A и положение карты; причина не обязательно в ключе.")
    except CardReadError as exc:
        print(f"Блок не прочитан (статус {exc.status:#04x}). Проверьте положение карты и права доступа.")
    except ReaderNotFoundError:
        print("Подключите считыватель по USB.")
    except ReaderOpenError:
        print("Не удалось открыть считыватель. Закройте nfcPro и проверьте подключение.")
    except ReaderTimeoutError as exc:
        print(f"Нет ответа от считывателя на этапе {exc.stage}. Проверьте подключение и повторите.")
    except USBError as exc:
        print(f"Сбой USB на этапе {exc.stage}: {exc}")
    except RFIDError as exc:
        # Например, несколько устройств, неизвестная карта, ошибка протокола.
        print(f"{exc.code}, этап {exc.stage}: {exc}")
    else:
        print(f"Число на карте: {number}")
        return 0
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyboardInterrupt, EOFError):
        print("\nЧтение отменено.")
        raise SystemExit(130)
