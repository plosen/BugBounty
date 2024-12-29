# tester.py
import requests
import logging
from api_integration import ask_chatgpt
import json
import time
from config import API_URL, API_KEY, HEADERS

# Настройка логирования для тестов
test_logger = logging.getLogger('tests')
test_logger.setLevel(logging.INFO)
test_handler = logging.FileHandler('tests_log.txt')
test_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
test_logger.addHandler(test_handler)

def send_request(method, url, headers=None, data=None, params=None):
    """
    Отправляет HTTP-запрос и возвращает ответ.
    """
    try:
        response = requests.request(method, url, headers=headers, data=data, params=params, timeout=10)
        return response
    except requests.exceptions.RequestException as e:
        error_message = f"Error sending {method} request to {url}: {str(e)}"
        logging.error(error_message)
        test_logger.error(error_message)
        return None

def perform_tests(subdomains):
    """
    Выполняет тестовые запросы к поддоменам и логирует результаты.
    """
    results = []
    for subdomain in subdomains.splitlines():
        subdomain = subdomain.strip()
        if not subdomain:
            continue
        url = f"http://{subdomain}"
        print(f"Performing tests on {url}...")
        test_logger.info(f"Testing {url}")

        # Пример GET-запроса
        response = send_request("GET", url)
        if response:
            test_details = f"{url} - GET - Status Code: {response.status_code}"
            results.append(test_details)
            test_logger.info(test_details)

        # Пример POST-запроса (можно адаптировать под конкретные нужды)
        post_data = {"test": "data"}
        response = send_request("POST", url, data=post_data)
        if response:
            test_details = f"{url} - POST - Status Code: {response.status_code}"
            results.append(test_details)
            test_logger.info(test_details)

        # Добавьте дополнительные типы запросов и тестов по необходимости

    return "\n".join(results)

def generate_test_plan(vulnerabilities, fuzz_results, sqlmap_results, code_analysis, wordlist_results, burp_results):
    """
    Генерирует план тестирования на основе собранных данных.
    """
    prompt = (
        f"На основе следующих данных:\n"
        f"Уязвимости:\n{vulnerabilities}\n"
        f"Фаззинг:\n{fuzz_results}\n"
        f"SQL-инъекции:\n{sqlmap_results}\n"
        f"Анализ кода:\n{code_analysis}\n"
        f"Тесты с wordlists:\n{wordlist_results}\n"
        f"Результаты BurpSuite:\n{burp_results}\n"
        f"Создай подробный план тестирования в формате JSON, включая типы HTTP-запросов, URL, заголовки и параметры для проверки."
    )
    test_plan_response = ask_chatgpt(prompt, max_tokens=1500)

    try:
        test_plan = json.loads(test_plan_response)
        return test_plan
    except json.JSONDecodeError:
        error_message = "Failed to parse test plan JSON from ChatGPT response."
        logging.error(error_message)
        test_logger.error(error_message)
        return None

def execute_test_plan(test_plan):
    """
    Выполняет тестовый план, предложенный ChatGPT.
    """
    if not test_plan or "tests" not in test_plan:
        error_message = "Invalid test plan format."
        logging.error(error_message)
        test_logger.error(error_message)
        return

    for test in test_plan["tests"]:
        method = test.get("method", "GET").upper()
        url = test.get("url")
        headers = test.get("headers")
        data = test.get("data")
        params = test.get("params")

        if not url:
            continue

        response = send_request(method, url, headers=headers, data=data, params=params)
        if response:
            test_details = f"{url} - {method} - Status Code: {response.status_code}"
            test_logger.info(test_details)
            print(test_details)
        else:
            test_details = f"{url} - {method} - Failed to get response."
            test_logger.info(test_details)
            print(test_details)
