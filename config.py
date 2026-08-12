import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parent


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "change-this-secret-key")
    NVD_API_KEY = os.getenv("NVD_API_KEY", "")
    NVD_DELAY = float(os.getenv("NVD_DELAY", "0.7"))
    NVD_RESULTS_PER_SERVICE = int(os.getenv("NVD_RESULTS_PER_SERVICE", "20"))
    MAX_CVES = int(os.getenv("MAX_CVES", "50"))
    NMAP_TIMEOUT = int(os.getenv("NMAP_TIMEOUT", "180"))

    REPORT_DIR = PROJECT_ROOT / "reports"
    EXPORT_DIR = PROJECT_ROOT / "app" / "static" / "exports"
    REPORT_PATH = REPORT_DIR / "report.pdf"
    JSON_PATH = EXPORT_DIR / "results.json"
    CSV_PATH = EXPORT_DIR / "results.csv"

    # PwnTrace deliberately does not execute exploits.
    ALLOW_EXPLOIT_EXECUTION = False
