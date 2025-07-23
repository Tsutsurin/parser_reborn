import logging
from pathlib import Path

class Logger:
    def __init__(self, enable_logs=False):
        self.enable_logs = enable_logs
        if enable_logs:
            Path('logs').mkdir(exist_ok=True)
            log_file = 'logs/vuln_parser.log'  # Один файл для всех логов
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - %(message)s',
                handlers=[
                    logging.FileHandler(log_file, mode='a'),  # Перезапись файла при запуске
                    logging.StreamHandler()
                ]
            )
            logging.getLogger('selenium').setLevel(logging.WARNING)
            self.logger = logging.getLogger(__name__)
        else:
            self.logger = None

    def info(self, msg):
        print(f"[INFO] {msg}")
        if self.enable_logs and self.logger:
            self.logger.info(msg)

    def warning(self, msg):
        print(f"[WARNING] {msg}")
        if self.enable_logs and self.logger:
            self.logger.warning(msg)

    def error(self, msg):
        print(f"[ERROR] {msg}")
        if self.enable_logs and self.logger:
            self.logger.error(msg)

    def debug(self, msg):
        if self.enable_logs and self.logger:
            self.logger.debug(msg)
