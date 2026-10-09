"""События карт в консоли. Остановка: Ctrl+C."""
import argparse
import logging
import sys
from wcopy_reader import watch_cards, CardPresented


def main():
    parser = argparse.ArgumentParser(description="Чтение карт со светом и звуком считывателя")
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--log-file', metavar='PATH', help='Записать подробный UTF-8 журнал прямо в файл')
    parser.add_argument('--no-beep', action='store_true', help='Отключить только нашу команду писка, сохранив LED')
    parser.add_argument('--no-feedback', action='store_true', help='Прежний режим без команд LED/звука')
    args = parser.parse_args()
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.DEBUG if args.debug else logging.INFO)
    handlers = [console]
    if args.log_file:
        file_handler = logging.FileHandler(args.log_file, mode='w', encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        handlers.append(file_handler)
    logging.basicConfig(level=logging.DEBUG if args.debug or args.log_file else logging.INFO,
                        handlers=handlers, format='%(asctime)s.%(msecs)03d %(levelname)s:%(name)s:%(message)s',
                        datefmt='%H:%M:%S', force=True)
    log = logging.getLogger('watch')
    log.info('Закройте nfcPro. Прикладывайте карты. Остановка: Ctrl+C.')
    log.info('Режим: feedback=%s, sound=%s', not args.no_feedback, not args.no_beep)
    if not args.no_feedback:
        log.info('Команды LED включены; команда писка %s.', 'отключена' if args.no_beep else 'включена')
    try:
        for event in watch_cards(feedback=not args.no_feedback, sound=not args.no_beep):
            if isinstance(event, CardPresented):
                log.info('Новая карта: UID=%s, число=%s', event.uid.hex(' ').upper(), event.number)
            else:
                error = event.error
                log.error('Ошибка: %s; этап=%s; %s', error.code, error.stage, error)
    except KeyboardInterrupt:
        log.info('Наблюдение остановлено.')
    finally:
        logging.shutdown()


if __name__ == '__main__':
    main()
