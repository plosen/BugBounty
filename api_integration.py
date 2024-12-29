# api_integration.py
import openai
import os
import logging
from config import API_URL, API_KEY, HEADERS
from dotenv import load_dotenv

load_dotenv(dotenv_path='api.env')


# Настройка логирования для API.py
logging.basicConfig(
    filename='api_error_log.txt',
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.ERROR
)

# Рекомендуется хранить API-ключ в переменной окружения, например, OPENAI_API_KEY
openai_api_key = os.getenv("OPENAI_API_KEY")
print(f"OPENAI_API_KEY: {openai_api_key}")
if not openai_api_key:
    logging.error("OpenAI API key not found in environment variables.")
    raise EnvironmentError("OpenAI API key not found in environment variables.")
openai.api_key = openai_api_key

if not openai_api_key:
    logging.error("OpenAI API key not found in environment variables.")
    raise EnvironmentError("OpenAI API key not found in environment variables.")
openai.api_key = openai_api_key

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
