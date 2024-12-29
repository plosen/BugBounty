import openai
import os
import logging
import sqlite3
from config import API_URL, API_KEY, HEADERS
from dotenv import load_dotenv
import time

# Загружаем переменные окружения
load_dotenv(dotenv_path='api.env')

# Настройка логирования для API
logging.basicConfig(
    filename='api_error_log.txt',
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.ERROR
)

# Получаем API-ключ для OpenAI
openai_api_key = os.getenv("OPENAI_API_KEY")
if not openai_api_key:
    logging.error("OpenAI API key not found in environment variables.")
    raise EnvironmentError("OpenAI API key not found in environment variables.")
openai.api_key = openai_api_key


def create_db():
    """Создает базу данных и таблицу для хранения информации о уязвимостях и ответах от ChatGPT."""
    conn = sqlite3.connect('vulnerabilities.db')
    cursor = conn.cursor()

    # Создаем таблицу для хранения данных
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subdomains TEXT,
            vulnerability TEXT,
            chatgpt_response TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()


def save_vulnerability_to_db(subdomains, vulnerability, chatgpt_response):
    """Сохраняет данные об уязвимости и ответ от ChatGPT в базу данных."""
    conn = sqlite3.connect('vulnerabilities.db')
    cursor = conn.cursor()

    # Вставляем данные в таблицу
    cursor.execute('''
        INSERT INTO vulnerabilities (subdomains, vulnerability, chatgpt_response)
        VALUES (?, ?, ?)
    ''', (subdomains, vulnerability, chatgpt_response))

    conn.commit()
    conn.close()


def ask_chatgpt(prompt, model="gpt-4", max_tokens=10000):
    """
    Отправляет запрос к ChatGPT и возвращает ответ.
    """
    try:
        response = openai.ChatCompletion.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=max_tokens,
            temperature=0.7
        )
        return response.choices[0].message['content']
    except Exception as e:
        error_message = f"Error with ChatGPT API: {str(e)}"
        logging.error(error_message)
        return f"Error with ChatGPT API: {str(e)}"


def main():
    # Пример данных о найденной уязвимости (могут быть получены из логов инструментов)
    subdomains = "example.com, sub.example.com"
    sqlmap_results = """
        В поддомене example.com была обнаружена уязвимость SQL-инъекции на странице /login.
        Ввод данных не экранируется должным образом, что позволяет выполнить произвольный SQL-запрос.
    """
    burp_results = """
        На поддомене example.com была найдена уязвимость XSS в поле ввода комментариев.
        Не происходит экранирование ввода пользователя, что позволяет выполнить JavaScript код.
    """

    # Формируем запрос для ChatGPT по SQL-инъекции
    prompt_sql_injection = (
        f"На основе поддоменов:\n{subdomains}\n"
        f"Уязвимостей:\n{sqlmap_results}\n"
        f"Предложи PoC эксплойт для обнаруженной уязвимости SQL-инъекции."
    )

    # Формируем запрос для ChatGPT по XSS
    prompt_xss = (
        f"На основе поддоменов:\n{subdomains}\n"
        f"Уязвимостей:\n{burp_results}\n"
        f"Предложи PoC эксплойт для обнаруженной уязвимости XSS."
    )

    # Получаем ответы от ChatGPT
    response_sql_injection = ask_chatgpt(prompt_sql_injection)
    response_xss = ask_chatgpt(prompt_xss)

    # Выводим ответы в консоль
    print(f"Ответ ChatGPT для SQL-инъекции:\n{response_sql_injection}\n")
    print(f"Ответ ChatGPT для XSS:\n{response_xss}\n")

    # Сохраняем данные в базу данных
    save_vulnerability_to_db(subdomains, sqlmap_results, response_sql_injection)
    save_vulnerability_to_db(subdomains, burp_results, response_xss)


if __name__ == "__main__":
    create_db()  # Создаем базу данных и таблицу
    main()
