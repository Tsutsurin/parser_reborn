import logging
import os
from datetime import datetime
from src.html_parser import EdgeHTMLParser
from src.vulnerability_parser import VulnerabilityParser
from src.utils.logger import setup_logging
from src.exceptions import VulnParserError
import pandas as pd
import re

def validate_vuln_id(vuln_id):
    '''Проверяет, что ID уязвимости соответствует формату'''
    pattern = r'^\d{4}-\d+$'
    return bool(re.match(pattern, vuln_id))

def increment_vuln_id(vuln_id):
    '''Увеличивает ID уязвимости на 1, сохраняя формат'''
    year, number = vuln_id.split('-')
    number = str((int(number) + 1)).zfill(len(number))
    return f'{year}-{number}'

def main():
    setup_logging()
    logger = logging.getLogger(__name__)

    while True:
        start_vuln_id = input('Введите начальный ID уязвимости (например, 2025-00000): ')
        if validate_vuln_id(start_vuln_id):
            break
        else:
            print('Некорректный формат ID. Попробуйте еще раз.')

    base_url = 'https://bdu.fstec.ru/vul/'
    all_vuln_data = []
    vuln_id = start_vuln_id
    url_exists = True

    while url_exists:
        url = f'{base_url}{vuln_id}'

        try:
            logger.info(f'Processing URL: {url}')

            driver = EdgeHTMLParser(
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0',
                headless=True,
                driver_path='drivers/msedgedriver.exe'
            )

            parser = VulnerabilityParser()
            html = driver.fetch_html(url)
            logger.info('Page loaded successfully')

            vuln_data = parser.parse_vulnerability_data(html, url)

            # Проверка флага остановки
            if not vuln_data.empty and 'should_stop' in vuln_data.columns and vuln_data.iloc[0]['should_stop']:
                logger.warning('Stop condition met. Ending processing.')
                url_exists = False
                break

            if vuln_data.empty:
                logger.warning('No valid vulnerability data found. Ending processing.')
                url_exists = False
                break

            logger.info('Successfully parsed data:\n%s', vuln_data.drop(columns=['should_stop'], errors='ignore').to_string(index=False))
            all_vuln_data.append(vuln_data.drop(columns=['should_stop'], errors='ignore'))
            vuln_id = increment_vuln_id(vuln_id)

        except VulnParserError as e:
            logger.error(f'Vulnerability parser error: {e}')
            url_exists = False
        except Exception as e:
            logger.error(f'Unexpected error: {e}', exc_info=True)
            url_exists = False
        finally:
            logger.info(f'Finished processing URL: {url}')

    if all_vuln_data:
        combined_df = pd.concat(all_vuln_data, ignore_index=True)
        
        if not os.path.exists('results'):
            os.makedirs('results')

        output_file = f'results/vulnerability_combined_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
        try:
            if not combined_df.empty:
                combined_df.to_excel(output_file, index=False)
                logger.info(f'Saved results to {output_file}')
            else:
                logger.warning('No data to save - empty DataFrame')
        except Exception as e:
            logger.error(f'Failed to save results: {e}')
    else:
        logger.warning('No vulnerability data collected')

if __name__ == '__main__':
    main()
