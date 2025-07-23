from selenium.webdriver import Edge
from selenium.webdriver.edge.service import Service
from selenium.webdriver.edge.options import Options
import time
import os
import sys
import logging
from typing import Optional
from src.exceptions import DriverNotFoundError, PageLoadError, PageNotFoundError

class EdgeHTMLParser:
    def __init__(self, user_agent: str = None, headless: bool = True, 
                 driver_path: str = None, ignore_cert_errors: bool = True):
        self.options = self._configure_options(user_agent, headless, ignore_cert_errors)
        self.driver_path = driver_path or self._find_default_driver_path()
        self.driver = Edge(service=Service(executable_path=self.driver_path), options=self.options)

    def _configure_options(self, user_agent: Optional[str], headless: bool, 
                         ignore_cert_errors: bool) -> Options:
        options = Options()
        if user_agent:
            options.add_argument(f'user-agent={user_agent}')
        if headless:
            options.add_argument('--headless=new')
        
        options.add_argument('--disable-gpu')
        options.add_argument('--no-sandbox')
        options.add_argument('--window-size=1920,1080')
        options.add_argument('--disable-blink-features=AutomationControlled')
        
        if ignore_cert_errors:
            options.add_argument('--ignore-certificate-errors')
            options.add_argument('--allow-running-insecure-content')
        
        return options

    def _find_default_driver_path(self) -> str:
        if getattr(sys, 'frozen', False):
            base_dir = os.path.dirname(sys.executable)
        else:
            base_dir = os.path.dirname(os.path.abspath(__file__))
        
        local_driver_path = os.path.join(base_dir, 'drivers', 'msedgedriver.exe')
        if os.path.exists(local_driver_path):
            return local_driver_path
            
        possible_paths = [
            os.path.join(os.environ.get('ProgramFiles(x86)', ''), 'Microsoft', 'Edge', 'Application', 'msedgedriver.exe'),
            os.path.join(os.environ.get('ProgramFiles', ''), 'Microsoft', 'Edge', 'Application', 'msedgedriver.exe'),
            'msedgedriver.exe'
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
                
        raise DriverNotFoundError('Edge driver not found. Please place msedgedriver.exe in the \'drivers\' folder.')

    def fetch_html(self, url: str, wait_time: int = 10, max_retries: int = 3) -> str:
        logger = logging.getLogger(__name__)

        for attempt in range(max_retries):
            try:
                self.driver.get(url)
                time.sleep(wait_time)
                page_source = self.driver.page_source
                if "Ошибка 404" in page_source:
                    logger.error(f"Page not found (404): {url}")
                    raise PageNotFoundError("Page not found (404)")
                return page_source
            except PageNotFoundError as e:
                raise e
            except Exception as e:
                if attempt < max_retries - 1:
                    logger.warning(f"Attempt {attempt + 1} failed for {url}: {str(e)}. Retrying...")
                    time.sleep(5)
                else:
                    logger.error(f"Failed to load {url} after {max_retries} attempts: {str(e)}")
                    raise PageLoadError(f"Failed to load {url} after {max_retries} attempts: {str(e)}")

    def close(self):
        if self.driver:
            self.driver.quit()
