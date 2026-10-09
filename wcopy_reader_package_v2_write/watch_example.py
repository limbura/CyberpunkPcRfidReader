"""События карт в консоли. Остановка: Ctrl+C."""
from wcopy_reader import watch_cards, CardPresented


def main():
    print('Закройте nfcPro. Прикладывайте карты. Остановка: Ctrl+C.')
    for event in watch_cards():
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
