# tools.py
import subprocess
import logging
import os
from config import (
    AMASS_PATH, NMAP_PATH, NIKTO_PATH, FFUF_PATH,
    SQLMAP_PATH, BANDIT_PATH, WFUZZ_PATH,
    BURP_SCANNER_PATH, COMMON_WORDLIST, SECLISTS_WORDLIST,
    BURP_REPORT_DIR
)

# Настройка логирования для инструментов
logging.basicConfig(
    filename='tools_error_log.txt',
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.ERROR
)

# Логгер для уязвимостей
vuln_logger = logging.getLogger('vulnerabilities')
vuln_logger.setLevel(logging.INFO)
vuln_handler = logging.FileHandler('vulnerabilities_log.txt')
vuln_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
vuln_logger.addHandler(vuln_handler)

def run_kali_tool(command):
    """Запускает Kali Linux инструмент через subprocess и возвращает результат."""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        error_message = f"Error running command '{command}': {e.stderr}"
        logging.error(error_message)
        return error_message
    except Exception as e:
        error_message = f"Unexpected error running command '{command}': {str(e)}"
        logging.error(error_message)
        return error_message

def enumerate_domains(domain):
    """Собирает поддомены с помощью amass."""
    command = f"{AMASS_PATH} enum -d {domain}"
    logging.info(f"Running amass enumeration for {domain}...")
    return run_kali_tool(command)

def scan_vulnerabilities(subdomains):
    """Сканирует уязвимости с помощью nmap и nikto."""
    results = []
    for subdomain in subdomains.splitlines():
        subdomain = subdomain.strip()
        if not subdomain:
            continue
        logging.info(f"Scanning {subdomain}...")
        nmap_command = f"{NMAP_PATH} -A {subdomain}"
        nikto_command = f"{NIKTO_PATH} -h {subdomain}"
        nmap_result = run_kali_tool(nmap_command)
        nikto_result = run_kali_tool(nikto_command)
        vulnerability_details = f"{subdomain}:\nNMAP:\n{nmap_result}\nNikto:\n{nikto_result}"
        results.append(vulnerability_details)
        vuln_logger.info(vulnerability_details)
    return "\n\n".join(results)

def fuzz_targets(subdomains):
    """Выполняет фаззинг с помощью ffuf."""
    results = []
    for subdomain in subdomains.splitlines():
        subdomain = subdomain.strip()
        if not subdomain:
            continue
        logging.info(f"Fuzzing {subdomain}...")
        ffuf_command = f"{FFUF_PATH} -u http://{subdomain}/FUZZ -w {COMMON_WORDLIST}"
        ffuf_result = run_kali_tool(ffuf_command)
        fuzz_details = f"{subdomain}:\nFFUF:\n{ffuf_result}"
        results.append(fuzz_details)
        vuln_logger.info(fuzz_details)
    return "\n\n".join(results)

def perform_sqlmap_scan(subdomains):
    """Проверяет SQL-инъекции с помощью sqlmap."""
    results = []
    for subdomain in subdomains.splitlines():
        subdomain = subdomain.strip()
        if not subdomain:
            continue
        logging.info(f"Running SQLMap on {subdomain}...")
        sqlmap_command = f"{SQLMAP_PATH} -u http://{subdomain} --batch --level=3"
        sqlmap_result = run_kali_tool(sqlmap_command)
        sqlmap_details = f"{subdomain}:\nSQLMap:\n{sqlmap_result}"
        results.append(sqlmap_details)
        vuln_logger.info(sqlmap_details)
    return "\n\n".join(results)

def analyze_code(directory):
    """Анализирует Python-код на уязвимости с помощью Bandit."""
    logging.info(f"Analyzing Python code in {directory}...")
    bandit_command = f"{BANDIT_PATH} -r {directory}"
    bandit_result = run_kali_tool(bandit_command)
    vuln_logger.info(f"Code Analysis:\n{bandit_result}")
    return bandit_result

def analyze_with_wordlists(subdomains):
    """Использует словари для поиска уязвимостей."""
    results = []
    for subdomain in subdomains.splitlines():
        subdomain = subdomain.strip()
        if not subdomain:
            continue
        logging.info(f"Testing wordlists on {subdomain}...")
        wfuzz_command = f"{WFUZZ_PATH} -u http://{subdomain}/FUZZ -w {SECLISTS_WORDLIST}"
        wfuzz_result = run_kali_tool(wfuzz_command)
        wordlist_details = f"{subdomain}:\nWFuzz:\n{wfuzz_result}"
        results.append(wordlist_details)
        vuln_logger.info(wordlist_details)
    return "\n\n".join(results)

def run_burp_suite(target):
    """Запускает BurpSuite для тестирования целевого поддомена."""
    try:
        logging.info(f"Running BurpSuite on {target}...")
        if not os.path.exists(BURP_SCANNER_PATH):
            error_message = f"BurpSuite Scanner not found at {BURP_SCANNER_PATH}."
            logging.error(error_message)
            return error_message

        # Формирование команды для запуска BurpSuite Scanner
        if not os.path.exists(BURP_REPORT_DIR):
            os.makedirs(BURP_REPORT_DIR)

        report_file = os.path.join(BURP_REPORT_DIR, f"burp_report_{target.replace('.', '_')}.json")
        burp_command = f"{BURP_SCANNER_PATH} --target http://{target} --report {report_file}"
        burp_result = run_kali_tool(burp_command)

        # Считывание отчёта BurpSuite
        if os.path.exists(report_file):
            with open(report_file, 'r') as file:
                burp_report = file.read()
            os.remove(report_file)  # Удаление отчёта после чтения
        else:
            burp_report = "BurpSuite report not found."

        vuln_logger.info(f"{target}:\nBurpSuite:\n{burp_report}")
        return burp_report
    except Exception as e:
        error_message = f"Error running BurpSuite on {target}: {str(e)}"
        logging.error(error_message)
        return error_message
