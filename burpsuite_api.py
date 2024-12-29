# burpsuite_api.py

import requests
import logging
import time
from config import API_URL, API_KEY, HEADERS

# Настройка логирования
logging.basicConfig(
    filename='burp_suite_log.txt',
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

def start_burp_scan(target):
    """Запускает сканирование BurpSuite для указанного целевого поддомена."""
    logging.info(f"Starting BurpSuite scan for {target}...")
    data = {
        "target": f"http://{target}",
        "scan_type": "full"  # Пример параметра, измените по необходимости
    }
    try:
        response = requests.post(f"{API_URL}/burp_suite/scan", headers=HEADERS, json=data)
        if response.status_code == 201:
            task_id = response.json().get("task_id")
            logging.info(f"BurpSuite scan started for {target}. Task ID: {task_id}")
            return task_id
        else:
            logging.error(f"Failed to start BurpSuite scan for {target}. Status Code: {response.status_code}")
            logging.error(response.text)
            return None
    except Exception as e:
        logging.error(f"Error starting BurpSuite scan for {target}: {str(e)}")
        return None

def check_burp_scan_status(task_id):
    """Проверяет статус выполнения сканирования BurpSuite."""
    status_url = f"{API_URL}/burp_suite/scan/{task_id}"
    while True:
        try:
            response = requests.get(status_url, headers=HEADERS)
            if response.status_code == 200:
                status = response.json().get("status")
                logging.info(f"BurpSuite scan status for Task ID {task_id}: {status}")
                print(f"Текущий статус сканирования: {status}")
                if status in ["completed", "failed"]:
                    if status == "completed":
                        report = response.json().get("report")
                        logging.info(f"BurpSuite scan completed for Task ID {task_id}. Report: {report}")
                        print("Сканирование завершено. Отчёт:")
                        print(report)
                    else:
                        logging.error(f"BurpSuite scan failed for Task ID {task_id}.")
                        print("Сканирование не удалось.")
                    break
            else:
                logging.error(f"Error checking BurpSuite scan status. Status Code: {response.status_code}")
                logging.error(response.text)
                break
            time.sleep(10)  # Ждём 10 секунд перед повторной проверкой
        except Exception as e:
            logging.error(f"Error checking BurpSuite scan status: {str(e)}")
            break

def main():
    target = "example.com"  # Замените на нужный поддомен
    task_id = start_burp_scan(target)
    if task_id:
        check_burp_scan_status(task_id)
    else:
        print("Не удалось запустить сканирование BurpSuite.")

if __name__ == "__main__":
    main()
