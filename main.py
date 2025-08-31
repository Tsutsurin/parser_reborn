import os
import sys
import argparse
from datetime import datetime
import pandas as pd
import re
import time
import logging
from pathlib import Path
from src.html_parser import EdgeHTMLParser
from src.vulnerability_parser import VulnerabilityParser
from src.exceptions import VulnParserError, PageNotFoundError, PageLoadError

def validate_vuln_id(vuln_id: str) -> bool:
    '''Проверяет формат ID уязвимости (например, 2025-00000).'''
    pattern = r'^\d{4}-\d+$'
    return bool(re.match(pattern, vuln_id))

def increment_vuln_id(vuln_id: str) -> str:
    '''Увеличивает ID уязвимости на единицу, сохраняя формат.'''
    year, number = vuln_id.split('-')
    number = str(int(number) + 1)
    original_length = len(vuln_id.split('-')[1])
    return f'{year}-{number.zfill(original_length)}'

def get_driver_path() -> str:
    '''Возвращает путь к драйверу Edge.'''
    if getattr(sys, 'frozen', False):
        application_path = os.path.dirname(sys.executable)
    else:
        application_path = os.path.dirname(os.path.abspath(__file__))
    driver_path = os.path.join(application_path, 'drivers', 'msedgedriver.exe')
    return driver_path

def setup_logging(enable_logs: bool) -> None:
    '''Настраивает конфигурацию логирования.'''
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)
    logging.getLogger().addHandler(console_handler)
    
    if enable_logs:
        Path('logs').mkdir(exist_ok=True)
        log_file = 'logs/vuln_parser.log'
        file_handler = logging.FileHandler(log_file, mode='a')
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(formatter)
        logging.getLogger().addHandler(file_handler)
    
    logging.getLogger('selenium').setLevel(logging.WARNING)
    logging.getLogger().setLevel(logging.INFO)

def main() -> None:
    '''Основная функция для сбора данных об уязвимостях.'''
    parser = argparse.ArgumentParser(description='Сбор данных об уязвимостях с веб-сайта')
    parser.add_argument('--logs', action='store_true', help='Включить логирование в файл')
    args = parser.parse_args()
    
    setup_logging(args.logs)
    logger = logging.getLogger(__name__)
    
    # Получение начального ID уязвимости
    while True:
        start_vuln_id = input('Введите начальный ID уязвимости (например, 2025-00000): ')
        if validate_vuln_id(start_vuln_id):
            break
        logger.error('Некорректный формат ID. Попробуйте еще раз.')
    
    base_url = 'https://bdu.fstec.ru/vul/'
    all_vuln_data = []
    vuln_id = start_vuln_id
    
    # Инициализация парсера HTML
    try:
        driver = EdgeHTMLParser(
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0',
            headless=True,
            driver_path=get_driver_path()
        )
    except:
        input('Edge драйвер не соответсвует текущей версии браузера.\n'
              'Cкачайть драйвер можно на сайте https://developer.microsoft.com/en-us/microsoft-edge/tools/webdriver/?form=MA13LH \n'
              'После распакуйте архив и поместите msedgedriver.exe в папку \'drivers\'.')
        exit()

    # Подготовка директории и файла для пропущенных URL
    results_dir = os.path.join(os.path.dirname(get_driver_path()), '..', 'results')
    os.makedirs(results_dir, exist_ok=True)
    missed_urls_file = os.path.join(results_dir, 'missed_urls.txt')
    with open(missed_urls_file, 'w') as f:
        pass  # Очистка или создание файла
    
    try:
        continue_processing = True
        while continue_processing:
            url = f'{base_url}{vuln_id}'
            html = None
            # Попытки загрузки страницы
            for attempt in range(3):
                try:
                    logger.info(f'Обработка URL: {url} (Попытка {attempt+1})')
                    html = driver.fetch_html(url)
                    logger.info(f'Страница {url} успешно загружена')
                    break
                except PageLoadError as e:
                    if attempt < 2:
                        logger.warning(f'Попытка {attempt+1} не удалась для {url}: {e}. Повтор через 5 секунд...')
                        time.sleep(5)
                    else:
                        logger.error(f'Не удалось загрузить {url} после 3 попыток: {e}')
                        with open(missed_urls_file, 'a') as f:
                            f.write(f'{url}\n')
                except PageNotFoundError as e:
                    logger.info(f'Страница не найдена (404) для {url}: {e}. Завершаем обработку.')
                    continue_processing = False
                    break
            
            if not continue_processing:
                break
            
            if html is None:
                vuln_id = increment_vuln_id(vuln_id)
                continue
            
            # Парсинг данных
            try:
                parser = VulnerabilityParser()
                vuln_data = parser.parse_vulnerability_data(html, url)
                
                if vuln_data.empty or ('should_skip' in vuln_data.columns and vuln_data.iloc[0]['should_skip']):
                    logger.info(f'Страница {url} зарезервирована.')
                    with open(missed_urls_file, 'a') as f:
                            f.write(f'{url}\n')

                if vuln_data.empty or ('should_stop' in vuln_data.columns and vuln_data.iloc[0]['should_stop']):
                    logger.info(f'Выполнено условие остановки для {url}. Завершаем обработку.')
                    break

                logger.info('Данные успешно извлечены:\n' + vuln_data.drop(columns=['should_stop'], errors='ignore').to_string(index=False))
                all_vuln_data.append(vuln_data.drop(columns=['should_stop', 'should_skip'], errors='ignore'))
                vuln_id = increment_vuln_id(vuln_id)
            except VulnParserError as e:
                logger.error(f'Ошибка парсинга для {url}: {e}')
                vuln_id = increment_vuln_id(vuln_id)
                continue
        
        # Сохранение результатов
        if all_vuln_data:
            combined_df = pd.concat(all_vuln_data, ignore_index=True)
            output_file = os.path.join(results_dir, f'vulnerability_combined_{datetime.now().strftime('%d%m%Y')}.xlsx')
            try:
                if not combined_df.empty:
                    combined_df.to_excel(output_file, index=False)
                    logger.info(f'Результаты сохранены в {output_file}')
                else:
                    logger.warning('Нет данных для сохранения - пустой DataFrame')
            except Exception as e:
                logger.error(f'Не удалось сохранить результаты: {e}')
        else:
            logger.warning('Данные об уязвимостях не собраны')
    
    finally:
        driver.close()

if __name__ == '__main__':
    main()
    input('Для завершения нажмите Enter.')
