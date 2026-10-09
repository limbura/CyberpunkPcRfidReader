"""События карт в консоли. Остановка: Ctrl+C."""
import argparse
import logging
from wcopy_reader import watch_cards, CardPresented


def main():
    parser = argparse.ArgumentParser(description="Чтение карт со светом и звуком считывателя")
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--no-feedback', action='store_true', help='Прежний режим без команд LED/звука')
    args = parser.parse_args()
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    print('Закройте nfcPro. Прикладывайте карты. Остановка: Ctrl+C.')
    if not args.no_feedback:
        print('LED/звук включены. Совместимость цветов с прошивкой нужно проверить на устройстве.')
    for event in watch_cards(feedback=not args.no_feedback):
        if isinstance(event, CardPresented):
            print(f'Новая карта: UID={event.uid.hex(" ").upper()}, число={event.number}', flush=True)
        else:
            error = event.error
            print(f'Ошибка: {error.code}; этап={error.stage}; {error}', flush=True)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nНаблюдение остановлено.')
