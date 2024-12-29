# main.py
from tools import (
    run_kali_tool, enumerate_domains, scan_vulnerabilities, fuzz_targets,
    analyze_code, perform_sqlmap_scan, analyze_with_wordlists, run_burp_suite
)
from api_integration import ask_chatgpt
from tester import perform_tests, generate_test_plan, execute_test_plan
import logging
import os
import json
import argparse
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
        print(f"Enumerating subdomains for {domain}...")
        general_logger.info(f"Enumerating subdomains for {domain}.")
        subdomains = enumerate_domains(domain)
        print(f"Subdomains found:\n{subdomains}")
        general_logger.info(f"Subdomains found:\n{subdomains}")

        # 2. Сканирование уязвимостей
        print("\nScanning for vulnerabilities...")
        general_logger.info("Scanning for vulnerabilities.")
        vulnerabilities = scan_vulnerabilities(subdomains)
        print(f"Vulnerability Scan Results:\n{vulnerabilities}")
        general_logger.info(f"Vulnerability Scan Results:\n{vulnerabilities}")

        # 3. Фаззинг (fuzzing)
        print("\nFuzzing targets...")
        general_logger.info("Fuzzing targets.")
        fuzz_results = fuzz_targets(subdomains)
        print(f"Fuzzing Results:\n{fuzz_results}")
        general_logger.info(f"Fuzzing Results:\n{fuzz_results}")

        # 4. SQL-инъекции
        print("\nChecking for SQL Injection vulnerabilities...")
        general_logger.info("Checking for SQL Injection vulnerabilities.")
        sqlmap_results = perform_sqlmap_scan(subdomains)
        print(f"SQLMap Results:\n{sqlmap_results}")
        general_logger.info(f"SQLMap Results:\n{sqlmap_results}")

        # 5. Анализ кода
        print(f"\nAnalyzing code in directory: {code_directory}...")
        general_logger.info(f"Analyzing code in directory: {code_directory}.")
        code_analysis = analyze_code(code_directory)
        print(f"Code Analysis:\n{code_analysis}")
        general_logger.info(f"Code Analysis:\n{code_analysis}")

        # 6. Использование словарей
        print("\nTesting with wordlists...")
        general_logger.info("Testing with wordlists.")
        wordlist_results = analyze_with_wordlists(subdomains)
        print(f"Wordlist Analysis Results:\n{wordlist_results}")
        general_logger.info(f"Wordlist Analysis Results:\n{wordlist_results}")

        # 7. Тестирование с помощью BurpSuite
        print("\nRunning BurpSuite tests...")
        general_logger.info("Running BurpSuite tests.")
        burp_results = []
        for subdomain in subdomains.splitlines():
            subdomain = subdomain.strip()
            if not subdomain:
                continue
            burp_result = run_burp_suite(subdomain)
            burp_results.append(burp_result)
        burp_results_combined = "\n".join(burp_results)
        print(f"BurpSuite Results:\n{burp_results_combined}")
        general_logger.info(f"BurpSuite Results:\n{burp_results_combined}")

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
        print("\nGenerating test plan with ChatGPT...")
        general_logger.info("Generating test plan with ChatGPT.")
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
        print("\nPerforming automated tests...")
        general_logger.info("Performing automated tests.")
        test_results = perform_tests(subdomains)
        print(f"Automated Test Results:\n{test_results}")
        general_logger.info(f"Automated Test Results:\n{test_results}")

        print("\nTesting complete. Ensure compliance with Doppler's Bug Bounty rules.")
        general_logger.info("Bug Bounty Testing Completed Successfully.")

    except Exception as e:
        error_message = f"An unexpected error occurred: {str(e)}"
        logging.error(error_message)
        general_logger.error(error_message)
        print(error_message)

if __name__ == "__main__":
    main()
