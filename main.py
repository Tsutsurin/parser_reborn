import os
import sys
from datetime import datetime
import pandas as pd
import re
import time
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

def process_vulnerabilities(start_vuln_id: str, enable_logs: bool = False):
    # Настройка без логирования, так как вывод только print
    base_url = 'https://bdu.fstec.ru/vul/'
    all_vuln_data = []
    vuln_id = start_vuln_id
    
    try:
        driver = EdgeHTMLParser(
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0',
            headless=True,
            driver_path=get_driver_path()
        )
    except:
        print('Edge драйвер не соответствует текущей версии браузера.\n'
              'Скачайте драйвер на сайте https://developer.microsoft.com/en-us/microsoft-edge/tools/webdriver/?form=MA13LH \n'
              'После распакуйте архив и поместите msedgedriver.exe в папку \'drivers\'.')
        return

    results_dir = os.path.join(os.path.dirname(get_driver_path()), '..', 'results')
    os.makedirs(results_dir, exist_ok=True)
    missed_urls_file = os.path.join(results_dir, 'missed_urls.txt')
    with open(missed_urls_file, 'w') as f:
        pass
    
    try:
        continue_processing = True
        while continue_processing:
            url = f'{base_url}{vuln_id}'
            html = None
            for attempt in range(3):
                print(f'Обрабатываем ссылку {url}, попытка №{attempt+1}', end=' ')
                try:
                    html = driver.fetch_html(url)
                    print('успешно!')
                    break
                except PageLoadError:
                    if attempt < 2:
                        time.sleep(5)
                    else:
                        print('не успешно!')
                        with open(missed_urls_file, 'a') as f:
                            f.write(f'{url}\n')
                except PageNotFoundError:
                    print('не существует!')
                    continue_processing = False
                    break
            
            if not continue_processing:
                break
            
            if html is None:
                vuln_id = increment_vuln_id(vuln_id)
                continue
            
            try:
                parser = VulnerabilityParser()
                vuln_data = parser.parse_vulnerability_data(html, url)
                
                if vuln_data.empty or ('should_skip' in vuln_data.columns and vuln_data.iloc[0]['should_skip']):
                    with open(missed_urls_file, 'a') as f:
                        f.write(f'{url}\n')
                    vuln_id = increment_vuln_id(vuln_id)
                    continue
                
                if vuln_data.empty or ('should_stop' in vuln_data.columns and vuln_data.iloc[0]['should_stop']):
                    break

                all_vuln_data.append(vuln_data.drop(columns=['should_stop', 'should_skip'], errors='ignore'))
                vuln_id = increment_vuln_id(vuln_id)
            except VulnParserError:
                vuln_id = increment_vuln_id(vuln_id)
                continue
        
        if all_vuln_data:
            combined_df = pd.concat(all_vuln_data, ignore_index=True)
            output_file = os.path.join(results_dir, f'vulnerability_combined_{datetime.now().strftime('%d%m%Y')}.xlsx')
            if not combined_df.empty:
                combined_df.to_excel(output_file, index=False)
                with open(missed_urls_file, 'r') as f:
                    missed = f.read().strip()
                if missed:
                    print(f'Были пропущенные следующие ссылки: {missed}')
                print(f'Результат сохранен по пути: {output_file}')
            else:
                print('Нет данных для сохранения - пустой DataFrame')
        else:
            print('Данные об уязвимостях не собраны')
    
    finally:
        driver.close()

def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description='Сбор данных об уязвимостях с веб-сайта')
    parser.add_argument('--logs', action='store_true', help='Включить логирование в файл')  # Оставлено, но не используется для вывода
    args = parser.parse_args()
    
    while True:
        start_vuln_id = input('Введите начальный ID уязвимости (например, 2025-00000): ')
        if validate_vuln_id(start_vuln_id):
            break
        print('Некорректный формат ID. Попробуйте еще раз.')
    
    process_vulnerabilities(start_vuln_id, args.logs)
    input('Для завершения нажмите Enter.')

if __name__ == '__main__':
    main()
