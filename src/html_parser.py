from selenium.webdriver import Edge
from selenium.webdriver.edge.service import Service
from selenium.webdriver.edge.options import Options
import time
import os
from typing import Optional
from src.exceptions import DriverNotFoundError, PageLoadError

class EdgeHTMLParser:
    def __init__(self, user_agent: str = None, headless: bool = True, 
                 driver_path: str = None, ignore_cert_errors: bool = True):
        self.options = self._configure_options(user_agent, headless, ignore_cert_errors)
        self.driver_path = driver_path or self._find_default_driver_path()

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
        possible_paths = [
            os.path.join(os.environ.get('ProgramFiles(x86)', ''), 'Microsoft', 'Edge', 'Application', 'msedgedriver.exe'),
            os.path.join(os.environ.get('ProgramFiles', ''), 'Microsoft', 'Edge', 'Application', 'msedgedriver.exe'),
            'msedgedriver.exe'
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
                
        raise DriverNotFoundError("Edge driver not found. Please install Microsoft Edge.")

    def fetch_html(self, url: str, wait_time: int = 10) -> str:
        driver = None
        try:
            driver = Edge(
                service=Service(executable_path=self.driver_path),
                options=self.options
            )
            driver.get(url)
            time.sleep(wait_time)
            return driver.page_source
        except Exception as e:
            raise PageLoadError(f"Failed to load page: {str(e)}")
        finally:
            if driver:
                driver.quit()