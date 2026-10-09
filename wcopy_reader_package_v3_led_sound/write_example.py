"""Запись ID с обязательной проверкой: python write_example.py [ID] [--debug]."""
import argparse
import logging

from wcopy_reader import RFIDError, write_card_number


def main():
    parser = argparse.ArgumentParser(description="Запись ID в блок 1 и проверка чтением")
    parser.add_argument("number", nargs="?", type=int, help="ID: целое число 0..18446744073709551615")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    try:
        number = args.number
        if number is None:
            number = int(input("Введите ID для записи: ").strip(), 10)
        if not 0 <= number <= 18446744073709551615:
            raise ValueError("ID должен быть от 0 до 18446744073709551615")
        input(f"Приложите одну карту для записи ID {number} и нажмите Enter. "
              "Не убирайте карту до результата.")
        verified = write_card_number(number)
    except ValueError as error:
        print(f"Некорректный ID: {error}")
        return 2
    except RFIDError as error:
        print(f"Успех записи не подтверждён: {error.code}, этап {error.stage}: {error}")
        if error.stage in ("write", "verify", "close"):
            print("Данные карты уже могли измениться. Проверьте её через example.py.")
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\nОперация прервана. Если запись уже началась, проверьте ID через example.py.")
        return 130
    print(f"УСПЕХ: записан ID {verified}; обратное чтение подтвердило весь блок.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
