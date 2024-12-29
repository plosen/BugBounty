import logging
import os
import json
import argparse
import time
import sys
from tools import (
    run_kali_tool, enumerate_domains, scan_vulnerabilities, fuzz_targets,
    analyze_code, perform_sqlmap_scan, analyze_with_wordlists, run_burp_suite
)
from api_integration import ask_chatgpt
from tester import perform_tests, generate_test_plan, execute_test_plan
from config import DEFAULT_DOMAIN, DEFAULT_CODE_DIRECTORY
from api_integration import openai_api_key

# Настройка логирования для MAIN.py
logging.basicConfig(
    filename='main_error_log.txt',
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.ERROR
)

# Создание отдельного логгера для общих логов
general_logger = logging.getLogger('general')
general_logger.setLevel(logging.INFO)
general_handler = logging.FileHandler('general_log.txt')
general_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
general_logger.addHandler(general_handler)

def perform_task_with_progress(task_name, task_function, *args, **kwargs):
    """
    Общая функция для выполнения задач с таймером и индикатором.
    """
    print(f"🔄 {task_name} начинается...")
    general_logger.info(f"{task_name} начинается...")

    try:
        # Запускаем задачу в фоновом режиме с индикатором загрузки
        for _ in range(5):
            sys.stdout.write(".")
            sys.stdout.flush()
            time.sleep(1)

        # Основная задача
        result = task_function(*args, **kwargs)

        print(f"\n{task_name} завершено.")
        general_logger.info(f"{task_name} завершено. Результаты: {result}")
        
        return result

    except Exception as e:
        print(f"❌ Ошибка при выполнении задачи {task_name}: {str(e)}")
        general_logger.error(f"Ошибка при выполнении задачи {task_name}: {str(e)}")
        return None

def enumerate_domains_with_progress(domain):
    """
    Модифицированная версия функции `enumerate_domains` с индикатором прогресса.
    """
    print(f"🚀 Начинаю поиск поддоменов для {domain}...")
    general_logger.info(f"Начинаю поиск поддоменов для {domain}.")

    # Инициализация индикатора
    try:
        # Запуск самой команды или процесса для поиска поддоменов
        subdomains = enumerate_domains(domain)

        # Для имитации времени выполнения, например, таймер на 5 секунд (замените на вашу логику)
        for _ in range(5):
            sys.stdout.write(".")
            sys.stdout.flush()
            time.sleep(1)

        print("\nПоддомены успешно найдены.")
        general_logger.info(f"Поддомены успешно найдены для {domain}: {subdomains}")
        
        return subdomains

    except Exception as e:
        print(f"❌ Ошибка при поиске поддоменов: {str(e)}")
        general_logger.error(f"Ошибка при поиске поддоменов для {domain}: {str(e)}")
        return []

def main():
    # Парсинг аргументов командной строки
    parser = argparse.ArgumentParser(description="Automated Bug Bounty Testing Tool")
    parser.add_argument("-d", "--domain", default=DEFAULT_DOMAIN, help="Target domain for testing")
    parser.add_argument("-c", "--code_dir", default=DEFAULT_CODE_DIRECTORY, help="Directory of the project code for analysis")
    args = parser.parse_args()

    domain = args.domain
    code_directory = args.code_dir

    print("Starting Automated Bug Bounty Testing with Enhanced Tools...\n")
    general_logger.info("Bug Bounty Testing Started.")

    try:
        # 1. Сбор поддоменов
        subdomains = enumerate_domains_with_progress(domain)

        # 2. Сканирование уязвимостей
        vulnerabilities = perform_task_with_progress("Сканирование уязвимостей", scan_vulnerabilities, subdomains)

        # 3. Фаззинг (fuzzing)
        fuzz_results = perform_task_with_progress("Фаззинг", fuzz_targets, subdomains)

        # 4. SQL-инъекции
        sqlmap_results = perform_task_with_progress("Проверка на SQL инъекции", perform_sqlmap_scan, subdomains)

        # 5. Анализ кода
        code_analysis = perform_task_with_progress("Анализ кода", analyze_code, code_directory)

        # 6. Использование словарей
        wordlist_results = perform_task_with_progress("Тестирование с словарями", analyze_with_wordlists, subdomains)

        # 7. Тестирование с помощью BurpSuite
        burp_results = []
        for subdomain in subdomains.splitlines():
            subdomain = subdomain.strip()
            if subdomain:
                burp_result = run_burp_suite(subdomain)
                burp_results.append(burp_result)
        burp_results_combined = "\n".join(burp_results)

        # 8. Генерация PoC эксплойта с помощью ChatGPT
        prompt = (
            f"На основе поддоменов:\n{subdomains}\n"
            f"Уязвимостей:\n{vulnerabilities}\n"
            f"Фаззинга:\n{fuzz_results}\n"
            f"SQL-инъекций:\n{sqlmap_results}\n"
            f"Анализа кода:\n{code_analysis}\n"
            f"Тестов с wordlists:\n{wordlist_results}\n"
            f"Результатов BurpSuite:\n{burp_results_combined}\n"
            f"Предложи PoC эксплойт."
        )
        exploit = ask_chatgpt(prompt)
        print("\nGenerated PoC Exploit:")
        print(exploit)
        general_logger.info(f"Generated PoC Exploit:\n{exploit}")

        # 9. Генерация и выполнение тестового плана с помощью ChatGPT
        test_plan = generate_test_plan(
            vulnerabilities, fuzz_results, sqlmap_results, code_analysis, wordlist_results, burp_results_combined
        )
        if test_plan:
            print("\nGenerated Test Plan:")
            print(json.dumps(test_plan, indent=4, ensure_ascii=False))
            general_logger.info(f"Generated Test Plan:\n{json.dumps(test_plan, indent=4, ensure_ascii=False)}")

            print("\nExecuting test plan...")
            execute_test_plan(test_plan)
            general_logger.info("Executed test plan.")
        else:
            print("Failed to generate a valid test plan.")
            general_logger.error("Failed to generate a valid test plan.")

        # 10. Выполнение автоматических тестов
        test_results = perform_task_with_progress("Автоматические тесты", perform_tests, subdomains)

        print("\nTesting complete. Ensure compliance with Doppler's Bug Bounty rules.")
        general_logger.info("Bug Bounty Testing Completed Successfully.")

    except Exception as e:
        error_message = f"An unexpected error occurred: {str(e)}"
        logging.error(error_message)
        general_logger.error(error_message)
        print(error_message)

if __name__ == "__main__":
    main()
