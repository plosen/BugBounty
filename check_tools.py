# check_tools.py

import os
import subprocess
import logging
from config import (
    AMASS_PATH, NMAP_PATH, NIKTO_PATH, FFUF_PATH,
    SQLMAP_PATH, BANDIT_PATH, WFUZZ_PATH,
    BURP_SCANNER_PATH, COMMON_WORDLIST, SECLISTS_WORDLIST
)

# Настройка логирования
logging.basicConfig(
    filename='tools_check_log.txt',
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# Список инструментов для проверки с их командами версии
TOOLS = {
    "Amass": {
        "path": AMASS_PATH,
        "version_cmd": ["-version"],  # Подкоманда для Amass
        "description": "Tool for in-depth DNS enumeration and asset discovery."
    },
    "Nmap": {
        "path": NMAP_PATH,
        "version_cmd": ["--version"],  # Флаг для Nmap
        "description": "Network scanner for discovering devices and services."
    },
    "Nikto": {
        "path": NIKTO_PATH,
        "version_cmd": ["-Version"],  # Флаг для Nikto
        "description": "Web server scanner for detecting vulnerabilities."
    },
    "FFUF": {
        "path": FFUF_PATH,
        "version_cmd": ["-V"],  # Флаг для FFUF
        "description": "Fast web fuzzer for discovering hidden directories and files."
    },
    "SQLMap": {
        "path": SQLMAP_PATH,
        "version_cmd": ["--version"],  # Флаг для SQLMap
        "description": "Automated tool for detecting and exploiting SQL injection flaws."
    },
    "Bandit": {
        "path": BANDIT_PATH,
        "version_cmd": ["--version"],  # Флаг для Bandit
        "description": "Security linter for Python code."
    },
    "WFuzz": {
        "path": WFUZZ_PATH,
        "version_cmd": ["--version"],  # Флаг для WFuzz
        "description": "Web fuzzer for discovering hidden resources and vulnerabilities."
    },
    "BurpSuite Scanner": {
        "path": BURP_SCANNER_PATH,
        "version_cmd": [],  # BurpSuite Scanner не поддерживает команду версии
        "description": "Comprehensive web vulnerability scanner."
    }
}

WORDLISTS = {
    "Common Wordlist": COMMON_WORDLIST,
    "SecLists Wordlist": SECLISTS_WORDLIST
}

def is_executable(file_path):
    """Проверяет, является ли файл исполняемым."""
    return os.path.isfile(file_path) and os.access(file_path, os.X_OK)

def check_tool_availability(tool_name, tool_path):
    """Проверяет наличие и доступность инструмента."""
    if not os.path.exists(tool_path):
        logging.error(f"{tool_name} не найден по пути: {tool_path}")
        print(f"❌ {tool_name} не найден по пути: {tool_path}")
        return False
    if not is_executable(tool_path):
        logging.error(f"{tool_name} по пути {tool_path} не является исполняемым.")
        print(f"❌ {tool_name} по пути {tool_path} не является исполняемым.")
        return False
    logging.info(f"{tool_name} найден и доступен по пути: {tool_path}")
    print(f"✅ {tool_name} найден и доступен по пути: {tool_path}")
    return True

def check_tool_functionality(tool_name, tool_path, version_cmd):
    """Проверяет функциональность инструмента путем выполнения команды версии."""
    if not version_cmd:
        # Для BurpSuite Scanner пропускаем проверку версии
        logging.info(f"{tool_name} доступен и готов к использованию.")
        print(f"✅ {tool_name} доступен и готов к использованию.")
        return True
    cmd = [tool_path] + version_cmd
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            version_info = result.stdout.strip() if result.stdout else result.stderr.strip()
            logging.info(f"{tool_name} функционален. Версия: {version_info}")
            print(f"✅ {tool_name} функционален. Версия: {version_info}")
            return True
        else:
            logging.error(f"Ошибка при выполнении {tool_name}: {result.stderr.strip()}")
            print(f"❌ Ошибка при выполнении {tool_name}: {result.stderr.strip()}")
            return False
    except subprocess.TimeoutExpired:
        logging.error(f"Время выполнения команды для {tool_name} превысило предел.")
        print(f"❌ Время выполнения команды для {tool_name} превысило предел.")
        return False
    except Exception as e:
        logging.error(f"Не удалось проверить функциональность {tool_name}: {str(e)}")
        print(f"❌ Не удалось проверить функциональность {tool_name}: {str(e)}")
        return False

def check_wordlist_availability(wordlist_name, wordlist_path):
    """Проверяет наличие и доступность wordlist-а."""
    if not os.path.exists(wordlist_path):
        logging.error(f"{wordlist_name} не найден по пути: {wordlist_path}")
        print(f"❌ {wordlist_name} не найден по пути: {wordlist_path}")
        return False
    if not os.access(wordlist_path, os.R_OK):
        logging.error(f"{wordlist_name} по пути {wordlist_path} недоступен для чтения.")
        print(f"❌ {wordlist_name} по пути {wordlist_path} недоступен для чтения.")
        return False
    logging.info(f"{wordlist_name} найден и доступен: {wordlist_path}")
    print(f"✅ {wordlist_name} найден и доступен: {wordlist_path}")
    return True

def main():
    print("🔍 Проверка наличия и доступности инструментов и wordlist-ов...\n")
    all_checks_passed = True

    # Проверка инструментов
    for tool_name, tool_info in TOOLS.items():
        tool_path = tool_info["path"]
        version_cmd = tool_info["version_cmd"]
        description = tool_info.get("description", "")

        print(f"🔧 Проверка {tool_name}: {description}")
        available = check_tool_availability(tool_name, tool_path)
        if not available:
            all_checks_passed = False
            continue

        functional = check_tool_functionality(tool_name, tool_path, version_cmd)
        if not functional:
            all_checks_passed = False

    # Проверка wordlist-ов
    for wordlist_name, wordlist_path in WORDLISTS.items():
        print(f"📄 Проверка {wordlist_name}: {wordlist_path}")
        available = check_wordlist_availability(wordlist_name, wordlist_path)
        if not available:
            all_checks_passed = False

    if all_checks_passed:
        logging.info("Все инструменты и wordlist-и установлены и работают корректно.")
        print("\n✅ Все инструменты и wordlist-и установлены и работают корректно.")
    else:
        logging.error("Некоторые инструменты или wordlist-и отсутствуют или не работают корректно.")
        print("\n❌ Некоторые инструменты или wordlist-и отсутствуют или не работают корректно.")
        exit(1)

if __name__ == "__main__":
    main()
