import aiofiles
import aiohttp
import asyncio
import logging
import os
import re
import requests
import socket
import subprocess
import yaml
from datetime import datetime

PROGRAMM_PATH = "/opt/kata/"
TMP_PATH = f"{PROGRAMM_PATH}tmp/"
SERVICE_PATH = f"/etc/systemd/system/kata_api.service"
CERT_PATH = f"{PROGRAMM_PATH}cert/"
PRIVATE_KEY = f"{CERT_PATH}kata_key.key"
KATA_CERT_REQ = f"{CERT_PATH}kata_cert_req.csr"
KATA_CERT = f"{CERT_PATH}kata_cert.crt"
TLS_CERTIFICATE = f"{CERT_PATH}kata_cert.pem"
KATA_POLLER_LOG_PATH = f"{PROGRAMM_PATH}log/"  # <- можно посмотреть логи по этому пути для отладки
KATA_POLLER_LOG_FILE = f"{KATA_POLLER_LOG_PATH}/kata_poller.log"
KATA_RESPONSE_TOKEN = "{prog_tmp_dir}kata_{kata_inst}_response_token.txt"


if not os.path.exists(KATA_POLLER_LOG_PATH):
    # Создание папки с логами KATA по пути /opt/kata/log
    os.mkdir(KATA_POLLER_LOG_PATH)
    logging.info(f"INFO: Успешно создана папка с логами по пути {KATA_POLLER_LOG_PATH}.")

logging.basicConfig(filename=KATA_POLLER_LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")

if not os.path.exists(TMP_PATH):
    # Создание tmp папки для токенов KATA по пути /opt/kata/tmp
    os.mkdir(TMP_PATH)
    logging.info(f"INFO: Успешно создана tmp папка для токенов KATA по пути {TMP_PATH}.")

with open(f'{PROGRAMM_PATH}KATA_PARAMS.YAML', 'r') as installations_info_file:
    # Парсинг YAML файла для получения информации о сервисах
    installations_info = yaml.safe_load(installations_info_file)
    KATA_INSTANCES = installations_info['kata_installations']
    BROKER_IP = installations_info['broker_ip']
    logging.info("INFO: Успешно распаршен конфиг с параметрами для скрипта.")


def generating_tls_certificate():
    """Генерирует приватный ключ и самоподписанный TLS сертификата"""

    if not os.path.exists(CERT_PATH):
        os.mkdir(CERT_PATH)
    subprocess.run(["openssl", "genrsa", "-out", f"{PRIVATE_KEY}", "2048"])
    subprocess.run(
        ["openssl", "req", "-sha256", "-new", "-key", f"{PRIVATE_KEY}", "-out",
         f"{KATA_CERT_REQ}",
         "-subj",
         "/CN=localhost"])
    subprocess.run(["openssl", "x509", "-req", "-sha256", "-days", "365", "-in",
                    f"{KATA_CERT_REQ}", "-signkey",
                    f"{PRIVATE_KEY}", "-out", f"{KATA_CERT}"])

    with open(f"{TLS_CERTIFICATE}", "wb") as pem_file:
        subprocess.run(["cat", f"{KATA_CERT}",
                        f"{PRIVATE_KEY}"], stdout=pem_file)
    logging.info("INFO: Успешно созданы: самоподписанный TLS сертификат и приватный ключ для запросов.")
    return


def kata_service_creator():
    """Создаёт сервис linux, который будет вызывать скрипт каждые 30 секунд"""

    with open(SERVICE_PATH, 'w') as kata_service_file:
        kata_service_file.write(
            '[Unit]\n'
            'Description=KATA API SERVICE\n'
            'Wants=network-online.target\n'
            'After=network.target network-online.target\n'
            'Wants=kata_api.timer\n\n'
            '[Service]\n'
            'Type=simple\n'
            f'ExecStart=/usr/bin/python3 {PROGRAMM_PATH}{os.path.basename(__file__)}\n'
            'Restart=always\n'
            'RestartSec=0\n'
            'StartLimitInterval=0\n\n'
            '[Install]\n'
            'WantedBy=multi-user.target\n\n'
        )

    subprocess.run(["sudo", "systemctl", "daemon-reload"])
    subprocess.run(["sudo", "systemctl", "start", "kata_api.service"])
    subprocess.run(["sudo", "systemctl", "enable", "kata_api.service"])

    return


async def fetch_events(session, kata_instance):
    """Асинхронный запрос к KATA API."""

    url = f"https://{kata_instance['kata_ip_address']}:443/kata/events_api/v1/{kata_instance['UUID']}/events"

    local_kata_response_token = KATA_RESPONSE_TOKEN.format(prog_tmp_dir=TMP_PATH,
                                                      kata_inst=kata_instance['kata_ip_address'])

    if not os.path.exists(local_kata_response_token) or not os.path.getsize(local_kata_response_token):
        # Проверка на наличие токена (если его нет, то инициируется первый запрос, в котором вернётся токен)

        try:
            async with session.get(url, cert=(TLS_CERTIFICATE, PRIVATE_KEY), verify=False) as response:
                response.raise_for_status()
        except Exception as e:
            logging.error(f"ERROR:Ошибка при получении данных от {kata_instance['kata_ip_address']}: {e}")
            return

        if not response.text:
            logging.info(f"ERROR: Запрос по API от {kata_instance['kata_ip_address']} вернул пустое значение.")
            return

        response_json_format = response.json()

        if 'error' in list(response_json_format.keys()) and response_json_format['error'] == 'Unauthorized':
            logging.info("INFO: Статус: Unauthorized. "
                         "Ожидается подтверждение администратором KATA обработки запросов от внешней системы"
                         f" на хосте {kata_instance['kata_ip_address']}")
            return

        async with aiofiles.open(local_kata_response_token, "w") as token_file:
            await token_file.write(response_json_format['continuationToken'])

        logging.info(f"INFO: Успешно получен токен авторизации для хоста {kata_instance['kata_ip_address']}.")

        return await response_json_format

    with open(local_kata_response_token, "r") as f:
        continuation_token = f.read()

    if not continuation_token:
        logging.error("ERROR: Токен авторизации не обнаружен.")
        return

    kata_req_params = {
        "max_timeout": "PT30S",
        "continuation_token": continuation_token
    }

    try:
        async with session.get(url, params=kata_req_params,
                               cert=(TLS_CERTIFICATE, PRIVATE_KEY), verify=False) as response:
            response.raise_for_status()
    except Exception as e:
        logging.error(f"ERROR:Ошибка при получении данных от {kata_instance['kata_ip_address']}: {e}")
        return

    if not response.text:
        logging.info("ERROR: Запрос по API вернул пустое значение.")
        return

    response_json_format = response.json()

    if 'error' in list(response_json_format.keys()) and response_json_format['error'] == 'Unauthorized':
        logging.info("WARN: Статус: Unauthorized. "
                     f"Пропал доступ к API на хосте {kata_instance['kata_ip_address']}. "
                     "Ожидается подтверждение администратором KATA обработки запросов от внешней системы.")

    with open(local_kata_response_token, "w") as output_file:
        output_file.write(response_json_format['continuationToken'])
    logging.info(f"INFO: Успешно записан новый токен авторизации для {kata_instance['kata_ip_address']}.")


async def send_to_target(session, data):
    """Асинхронная отправка данных на целевой хост."""
    if not data:
        return
    try:
        async with session.post(TARGET_URL, json=data) as response:
            response.raise_for_status()
            print(f"Успешно отправлено: {await response.text()}")
    except Exception as e:
        print(f"Ошибка при отправке данных: {e}")


async def kata_async_request(session, kata_instance):
    """Обработка одной инсталляции KATA."""
    events = await fetch_events(session, kata_instance)
    if events:
        await send_to_target(session, events)


async def main():
    async with aiohttp.ClientSession() as session:
        tasks = [kata_async_request(session, instance) for instance in KATA_INSTANCES]
        await asyncio.gather(*tasks)


if __name__ == "__main__":
    if not os.path.exists(SERVICE_PATH) or not os.path.getsize(SERVICE_PATH) > 0:
        # Проверка на наличие сервиса
        kata_service_creator()
        logging.info("INFO: Сервис kata_api успешно создан.")

    if not os.path.exists(TLS_CERTIFICATE) or not os.path.exists(PRIVATE_KEY):
        generating_tls_certificate()
    logging.info("INFO: Самоподписанный TLS сертификат и приватный ключ обнаружены.")

    asyncio.run(main())

    log_file_size = os.path.getsize(KATA_POLLER_LOG_FILE)
    if log_file_size / (1024 * 1024) > 5:
        # Проверка на размер файла с логами (если больше 5 МБ, перезаписывается)
        with open(KATA_POLLER_LOG_FILE, "w"):
            pass
        logging.info("INFO: Файл успешно очищен, т.к. его размер был больше 5 МБ.")
    logging.info("INFO: Скрипт успешно завершил свою работу.")
