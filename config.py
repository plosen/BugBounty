# config.py

# Настройки API
API_URL = "http://127.0.0.1:1337/v0.1"  # Базовый URL API
API_KEY = "HhHxuvdxWFcxThrTQmzF9efRAAFxJEym"  # Ваш API-ключ
HEADERS = {"Authorization": f"Bearer {API_KEY}"}

# Настройки инструментов Kali Linux
AMASS_PATH = "/usr/bin/amass"
NMAP_PATH = "/usr/bin/nmap"
NIKTO_PATH = "/usr/bin/nikto"
FFUF_PATH = "/usr/bin/ffuf"
SQLMAP_PATH = "/usr/bin/sqlmap"
BANDIT_PATH = "/usr/bin/bandit"
WFUZZ_PATH = "/usr/bin/wfuzz"
BURP_SCANNER_PATH = "/usr/bin/burpsuite"  # Обновите путь при необходимости

# Настройки сканирования
COMMON_WORDLIST = "/usr/share/wordlists/dirb/common.txt"
SECLISTS_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/common.txt"

# Настройки BurpSuite
BURP_REPORT_DIR = "./burp_reports"

# Другие параметры
DEFAULT_DOMAIN = "doppler.com"  # Замените на нужный домен
DEFAULT_CODE_DIRECTORY = "doppler_project_directory"  # Замените на нужную директорию
