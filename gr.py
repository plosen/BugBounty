import requests
import time

# Настройки API
API_URL = "http://127.0.0.1:1337/v0.1"  # Базовый URL API
API_KEY = "HhHxuvdxWFcxThrTQmzF9efRAAFxJEym"  # Ваш API-ключ
HEADERS = {"Authorization": f"Bearer {API_KEY}"}

# Функция для проверки доступности API
def check_api_availability():
    print("Проверка доступности API...")
    try:
        response = requests.get(f"{API_URL}/openapi.json", headers=HEADERS)
        if response.status_code == 200:
            print("API доступно. Доступные эндпоинты:")
            print(response.json())  # Вывод структуры OpenAPI
        else:
            print(f"Ошибка: {response.status_code}")
            print(response.text)
    except Exception as e:
        print(f"Ошибка подключения к API: {str(e)}")

# Функция для получения списка уязвимостей
def get_issue_definitions():
    print("\nПолучение списка уязвимостей...")
    try:
        response = requests.get(f"{API_URL}/knowledge_base/issue_definitions", headers=HEADERS)
        if response.status_code == 200:
            print("Список уязвимостей:")
            print(response.json())
        else:
            print(f"Ошибка: {response.status_code}")
            print(response.text)
    except Exception as e:
        print(f"Ошибка при запросе уязвимостей: {str(e)}")

# Функция для запуска сканирования
def start_scan():
    print("\nЗапуск сканирования...")
    data = {
        "urls": ["http://example.com"]  # Замените на реальный URL
    }
    try:
        response = requests.post(f"{API_URL}/scan", headers=HEADERS, json=data)
        if response.status_code == 201:
            print("Сканирование успешно запущено!")
            task_id = response.headers.get("Location")  # Получаем идентификатор задачи
            print(f"Идентификатор задачи: {task_id}")
            # Формируем полный URL для проверки статуса
            status_url = f"{API_URL}/scan/{task_id}"
            print(f"URL для статуса сканирования: {status_url}")
            return status_url  # Возвращаем полный URL
        else:
            print(f"Ошибка: {response.status_code}")
            print(response.text)
    except Exception as e:
        print(f"Ошибка при запуске сканирования: {str(e)}")
    return None

# Функция для проверки статуса сканирования
def check_scan_status(scan_url):
    print("\nПроверка статуса сканирования...")
    try:
        while True:
            response = requests.get(scan_url, headers=HEADERS)
            if response.status_code == 200:
                status = response.json().get("scan_status")
                print(f"Текущий статус: {status}")
                if status in ["succeeded", "failed"]:
                    print("Сканирование завершено.")
                    print(response.json())  # Вывод полного ответа
                    break
            else:
                print(f"Ошибка: {response.status_code}")
                print(response.text)
                break
            time.sleep(10)  # Ждём 10 секунд перед повторной проверкой
    except Exception as e:
        print(f"Ошибка при проверке статуса сканирования: {str(e)}")

# Основная функция
def main():
    # Шаг 1. Проверка доступности API
    check_api_availability()

    # Шаг 2. Получение списка уязвимостей
    get_issue_definitions()

    # Шаг 3. Запуск сканирования
    scan_url = start_scan()

    # Шаг 4. Проверка статуса сканирования
    if scan_url:
        check_scan_status(scan_url)
    else:
        print("Не удалось запустить сканирование. Пропуск проверки статуса.")

if __name__ == "__main__":
    main()
