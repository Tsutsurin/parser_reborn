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
    """Проверяет, что ID уязвимости соответствует формату ГГГГ-ЧЧЧ...Ч"""
    pattern = r"^\d{4}-\d+$"  # 4 цифры года, дефис, любое количество цифр
    return bool(re.match(pattern, vuln_id))

def increment_vuln_id(vuln_id):
    """Увеличивает ID уязвимости на 1, сохраняя формат"""
    year, number = vuln_id.split('-')
    number = int(number) + 1
    return f"{year}-{number}" # Возвращаем как строку без форматирования

def main():
    setup_logging()
    logger = logging.getLogger(__name__)

    while True:
        start_vuln_id = input("Введите начальный ID уязвимости в формате ГГГГ-ЧЧЧ...Ч (например, 2025-00000): ")
        if validate_vuln_id(start_vuln_id):
            break #Выходим из цикла, если ввод корректен
        else:
            print("Некорректный формат ID. Пожалуйста, введите в формате ГГГГ-ЧЧЧ...Ч.")

    # Базовый URL
    base_url = 'https://bdu.fstec.ru/vul/'


    # Инициализация списка для хранения данных
    all_vuln_data = []
    vuln_id = start_vuln_id
    url_exists = True  # Флаг для продолжения цикла

    while url_exists:
        try:
            url = base_url + vuln_id
            logger.info(f"Starting parser for {url}")

            driver = EdgeHTMLParser(
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0',
                headless=True,
                driver_path="drivers/msedgedriver.exe"
            )

            parser = VulnerabilityParser()

            html = driver.fetch_html(url)
            logger.info("Page loaded successfully")

            vuln_data = parser.parse_vulnerability_data(html)

            # Проверка данных перед сохранением
            if not vuln_data.empty:
                logger.info("Parsed data:\n%s", vuln_data.to_string(index=False))
                all_vuln_data.append(vuln_data)  # Добавляем DataFrame к общему списку
                vuln_id = increment_vuln_id(vuln_id) #Используем функцию для увеличения ID
            else:
                logger.warning("No vulnerability data found for %s", url)
                url_exists = False  # Прекращаем цикл, если данные не найдены

        except VulnParserError as e:
            logger.error(f"Vulnerability parser error for {url}: {e}")
            url_exists = False # Прекращаем цикл, если произошла ошибка при парсинге
        except Exception as e:
            logger.error(f"Unexpected error for {url}: {e}", exc_info=True)
            url_exists = False  # Прекращаем цикл при любой ошибке
        finally:
            logger.info("Parser finished for URL: %s", url)

    # Объединяем все DataFrame в один
    if all_vuln_data:
        combined_df = pd.concat(all_vuln_data, ignore_index=True)  # Объединяем все DataFrame в один

        # Проверка существования папки results
        if not os.path.exists('results'):
            os.makedirs('results')

        # Сохраняем объединенный DataFrame в один файл Excel
        output_file_combined = f"results/vulnerability_combined_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        try:
            if not combined_df.empty:
                logger.info(f"Saving combined results to {output_file_combined}")
                combined_df.to_excel(output_file_combined, index=False)
                logger.info(f"Combined results saved to {output_file_combined}")
            else:
                logger.warning("No combined vulnerability data to save.")
        except Exception as e:
            logger.error(f"Failed to save combined data to Excel: {e}", exc_info=True)
    else:
        logger.warning("No vulnerability data found for any URL in the range.")

if __name__ == '__main__':
    main()