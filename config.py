import os
from pathlib import Path

BASE_DIR = Path(__file__).parent.resolve()

DRIVERS_DIR = BASE_DIR / 'drivers'
LOGS_DIR = BASE_DIR / 'logs'
RESULTS_DIR = BASE_DIR / 'results'

for directory in [DRIVERS_DIR, LOGS_DIR, RESULTS_DIR]:
    directory.mkdir(exist_ok=True)
