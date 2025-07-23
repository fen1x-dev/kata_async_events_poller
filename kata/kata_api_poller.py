#!/usr/bin/python3
import aiofiles
import aiohttp
import asyncio
import json
import logging
import os
import re
import ssl
import subprocess
import sys
import time
import yaml
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler

__version__ = "1.0.5"
__date__ = "2025-07-23"
PROGRAM_PATH = "/opt/kata/"  # <- директория с компонентами программы
KATA_PARAMS_FILE = f"{PROGRAM_PATH}KATA_PARAMS.YAML"
REQUIREMENTS_FILE = f"{PROGRAM_PATH}requirements.txt"
TMP_PATH = f"{PROGRAM_PATH}tmp/"  # <- директория с токенами для запросов в KATA
SERVICE_PATH = f"/etc/systemd/system/kata_api.service"
CERT_PATH = f"{PROGRAM_PATH}cert/"  # <- директория с сертификатом и приватным ключом
PRIVATE_KEY = f"{CERT_PATH}kata_key.key"
KATA_CERT_REQ = f"{CERT_PATH}kata_cert_req.csr"
KATA_CERT = f"{CERT_PATH}kata_cert.crt"
TLS_CERTIFICATE = f"{CERT_PATH}kata_cert.pem"
KATA_POLLER_LOG_PATH = f"{PROGRAM_PATH}log/"  # <- директория с логами программы, можно посмотреть для отладки
KATA_POLLER_LOG_FILE = f"{KATA_POLLER_LOG_PATH}kata_poller.log"
KATA_RESPONSE_TOKEN = "{prog_tmp_dir}kata_{kata_inst}_response_token.txt"
SYSLOG_PORT = 514  # <- порт для отправки событий syslog в формате RFC3164
LOG_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL
}

logger = logging.getLogger()
logger.setLevel(LOG_LEVELS.get("INFO"))

file_handler = TimedRotatingFileHandler(
    filename=KATA_POLLER_LOG_FILE,
    when="midnight",
    interval=1,
    backupCount=7,
    encoding='utf-8',
    utc=False
)

file_handler.suffix = "%Y-%m-%d"

formatter = logging.Formatter("%(asctime)s - %(levelname)s: %(message)s")

file_handler.setFormatter(formatter)
file_handler.setLevel(LOG_LEVELS.get("INFO"))

if not logger.hasHandlers():
    logger.addHandler(file_handler)

logging.info(f"Скрипт запущен: версия скрипта: {__version__}, дата обновления скрипта: {__date__}.")

if not os.path.exists(KATA_PARAMS_FILE):
    logging.error(f"Отсутствует конфигурационный файл по пути {KATA_PARAMS_FILE}.")
    sys.exit(1)
else:
    logging.debug(f"Файл {KATA_PARAMS_FILE} с конфигурацией обнаружен.")

# Парсинг YAML файла для получения информации о сервисах
with open(KATA_PARAMS_FILE, 'r') as installations_info_file:
    # TODO Вынести валидацию YAML конфига в отдельную функцию
    # TODO Добавить валидацию IP-адреса
    installations_info = yaml.safe_load(installations_info_file)
    LOGGING_LEVEL = installations_info.get("logging_level", "INFO").upper()
    if LOGGING_LEVEL in LOG_LEVELS:
        level = LOG_LEVELS.get(LOGGING_LEVEL, logging.INFO)
        logger.setLevel(level)
        file_handler.setLevel(level)
    else:
        logging.warning(f"Параметр {LOGGING_LEVEL} - неверный. Выберите один из допустимых: "
                        f"DEBUG, INFO, WARNING, ERROR, CRITICAL")
    KATA_INSTANCES = installations_info.get("kata_installations", None)
    if not KATA_INSTANCES:
        logging.error(f"Отсутствует параметр 'kata_installations' в конфигурационном файле: {KATA_PARAMS_FILE}.")
        sys.exit(1)
    BROKER_IP = installations_info.get("broker_ip", None)
    if not BROKER_IP:
        logging.error(f"Отсутствует параметр 'broker_ip' в конфигурационном файле: {KATA_PARAMS_FILE}.")
        sys.exit(1)

    for i_installation in KATA_INSTANCES:
        kata_ip_validate = i_installation.get('kata_ip_address', None)
        if not kata_ip_validate:
            logging.error(
                "Отсутствует IP-адрес в массиве 'kata_installations' "
                f"в конфигурационном файле: {KATA_PARAMS_FILE}.")
            sys.exit(1)
        kata_uuid_validate = i_installation.get('UUID', None)
        if not kata_uuid_validate:
            logging.error(
                "Отсутствует идентификатор UUID в массиве 'kata_installations' "
                f"в конфигурационном файле: {KATA_PARAMS_FILE} для инсталляции KATA с IP-адресом {kata_ip_validate}.")
            sys.exit(1)

    CA_FILE_PATH = installations_info.get("ca_file_path", None)
    if not CA_FILE_PATH:
        logging.debug("Файл с корневым CA не обнаружен.")
    else:
        logging.debug(f"Файл с корневым CA обнаружен по пути {CA_FILE_PATH}.")

    logging.info("Успешно распаршен конфиг с параметрами для скрипта.")

if not os.path.exists(TMP_PATH):
    # Создание tmp директории для токенов KATA по пути /opt/kata/tmp
    os.makedirs(TMP_PATH, exist_ok=True)
    logging.info(f"Успешно создана tmp директория для токенов KATA по пути {TMP_PATH}.")
else:
    logging.debug(f"Директория tmp для токенов KATA по пути {TMP_PATH} обнаружена.")


if not os.path.exists(CERT_PATH):
    # Создание cert директории с сертификатами для запросов в KATA по пути /opt/kata/cert
    os.makedirs(CERT_PATH, exist_ok=True)
    logging.info(f"Успешно создана директория cert для сертификатов по пути {CERT_PATH}.")
else:
    logging.debug(f"Директория cert для сертификатов по пути {CERT_PATH} обнаружена.")


def generating_tls_certificate():
    """Генерирует приватный ключ и самоподписанный TLS сертификат"""

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
        subprocess.run(["cat", f"{KATA_CERT}", f"{PRIVATE_KEY}"], stdout=pem_file)
    logging.info("Успешно созданы: самоподписанный TLS сертификат и приватный ключ для запросов.")

    return


def kata_service_creator():
    """Создаёт сервис linux, который будет циклично вызывать скрипт после завершения его выполнения"""

    with open(SERVICE_PATH, 'w') as kata_service_file:
        kata_service_file.write(
            '[Unit]\n'
            'Description=KATA API SERVICE\n'
            'Wants=network-online.target\n'
            'After=network.target network-online.target\n\n'
            '[Service]\n'
            'Type=simple\n'
            f'ExecStart=/usr/bin/python3 {PROGRAM_PATH}{os.path.basename(__file__)}\n'
            'Restart=always\n'
            'RestartSec=0\n'
            'StartLimitInterval=0\n\n'
            '[Install]\n'
            'WantedBy=multi-user.target\n\n'
        )

    subprocess.run(["sudo", "systemctl", "daemon-reload"])
    subprocess.run(["sudo", "systemctl", "start", "kata_api.service"])
    subprocess.run(["sudo", "systemctl", "enable", "kata_api.service"])

    logging.info(f"Сервис kata_api создан по пути {SERVICE_PATH}.")
    return


async def fetch_events(session, kata_instance: dict):
    """
    Асинхронный запрос к KATA API.

    Parameters:
        session (aiohttp.ClientSession): Асинхронная сессия для HTTP-запросов.
        kata_instance (dict): Словарь с данными об инсталляции KATA (IP-адрес и UUID).
    """
    kata_ip = kata_instance.get("kata_ip_address")
    kata_uuid = kata_instance.get('UUID')

    url = f"https://{kata_ip}/kata/events_api/v1/{kata_uuid}/events"

    local_kata_response_token = KATA_RESPONSE_TOKEN.format(prog_tmp_dir=TMP_PATH, kata_inst=kata_ip)

    if not os.path.exists(local_kata_response_token) or not os.path.getsize(local_kata_response_token) > 0:
        # Проверка на наличие токена (если его нет, то инициируется первый запрос, в котором вернётся токен)
        logging.info(f"Направлен первичный запрос в {kata_ip} для получения токена, ожидается ответ.")

        try:
            if CA_FILE_PATH and os.path.exists(CA_FILE_PATH) and os.path.getsize(CA_FILE_PATH) > 0:
                logging.debug(f"Корневой сертификат для {kata_ip} успешно загружен из {CA_FILE_PATH}.")
                ssl_context = ssl.create_default_context(cafile=CA_FILE_PATH)
            else:
                logging.warning(f"Не найден валидный корневой сертификат для {kata_ip}. "
                                f"Будет установлено небезопасное SSL-соединение.")
                ssl_context = ssl._create_unverified_context()
            ssl_context.load_cert_chain(certfile=TLS_CERTIFICATE, keyfile=PRIVATE_KEY)

            async with session.get(url, ssl=ssl_context) as response:
                response.raise_for_status()
                response_text = await response.text()
                response_json_format = json.loads(response_text)
        except aiohttp.ClientResponseError as e:
            if e.status == 401:
                logging.warning("Статус - Unauthorized. "
                             "Ожидается подтверждение администратором KATA обработки запросов от внешней системы"
                             f" на хосте {kata_ip}")
            else:
                logging.error(f"Ошибка при получении данных от {kata_ip}: {e}")
                return
        except Exception as e:
            logging.error(f"Ошибка при получении данных от {kata_ip}: {e}")
            return


        async with aiofiles.open(local_kata_response_token, "w") as token_file:
            await token_file.write(response_json_format.get("continuationToken"))

        logging.info(f"Ответ получен. Успешно записан новый токен авторизации для хоста {kata_ip}.")

        await send_to_syslog(response_json_format.get("events"), kata_ip)

    continuation_token = None
    if os.path.exists(local_kata_response_token):
        async with aiofiles.open(local_kata_response_token, "r") as f:
            continuation_token = (await f.read()).strip()
        logging.debug(f"Токен авторизации для хоста {kata_ip} обнаружен.")
    else:
        logging.error(f"Отсутствует токен авторизации для хоста {kata_ip}.")
        return

    kata_req_params = {
        "max_timeout": "PT60S",
        "continuation_token": continuation_token
    }

    logging.info(f"Отправление запроса в {kata_ip} с токеном, ожидается ответ.")

    try:
        if CA_FILE_PATH and os.path.exists(CA_FILE_PATH) and os.path.getsize(CA_FILE_PATH) > 0:
            logging.debug(f"Корневой сертификат для {kata_ip} успешно загружен из {CA_FILE_PATH}.")
            ssl_context = ssl.create_default_context(cafile=CA_FILE_PATH)
        else:
            logging.warning(f"Не найден валидный корневой сертификат для {kata_ip}. "
                            f"Будет установлено небезопасное SSL-соединение.")
            ssl_context = ssl._create_unverified_context()
        ssl_context.load_cert_chain(certfile=TLS_CERTIFICATE, keyfile=PRIVATE_KEY)

        async with session.get(url, params=kata_req_params, ssl=ssl_context) as response:
            response.raise_for_status()
            response_text = await response.text()
            response_json_format = json.loads(response_text)
    except aiohttp.ClientResponseError as e:
        if e.status == 401:
            logging.warning(f"Статус: Unauthorized. Пропал доступ к API на хосте {kata_ip}. "
                         "Ожидается подтверждение администратором KATA обработки запросов от внешней системы.")
        else:
            logging.error(f"Ошибка при получении данных от {kata_ip}: {e}")
        return
    except Exception as e:
        logging.error(f"Ошибка при получении данных от {kata_ip}: {e}")
        return

    async with aiofiles.open(local_kata_response_token, "w") as token_file:
        await token_file.write(response_json_format['continuationToken'])
    logging.info(f"Ответ получен от {kata_ip}.")
    logging.debug(f"Успешно записан новый токен авторизации для {kata_ip}.")

    await send_to_syslog(response_json_format.get("events"), kata_ip)


def format_syslog_message(event: dict, kata_ip_address: str):
    """
    Форматирование Syslog-сообщения в RFC 3164.

    Parameters:
        event (dict): Словарь с данными о событии.
        kata_ip_address (str): IP-адрес инсталляции KATA.
    Returns:
        str: Строка с отформатированным Syslog-сообщением в формате RFC3164.
    """
    priority = "<134>"
    timestamp_micro = event.get('Timestamp', int(time.time() * 1_000_000))
    timestamp = datetime.fromtimestamp(timestamp_micro / 1_000_000.0).strftime('%b %d %H:%M:%S')
    hostname = kata_ip_address
    program = "KATA"
    message = f"{event}"

    return f"{priority}{timestamp} {hostname} {program}: {message}"


async def send_to_syslog(events: list, kata_ip_address: str):
    """
    Асинхронная отправка событий в Syslog (TCP 514).

    Parameters:
        events (list): Список событий, полученных из KATA за запрос.
        kata_ip_address (str): IP-адрес инсталляции KATA.
    """
    try:
        reader, writer = await asyncio.open_connection(BROKER_IP, SYSLOG_PORT)

        if events:
            for i_event in events:
                if 'Ioa' not in i_event:
                    continue
                if re.search(r'T\d{4}\w+', i_event.get("Ioa", {}).get("Rules", [{}])[0].get("Name", "")):
                    continue
                log_message = format_syslog_message(i_event, kata_ip_address)
                writer.write(log_message.encode('utf-8') + b'\n')
                await writer.drain()

        healthcheck_event = {
            "Timestamp": time.time_ns() // 1_000,
            "Message": "Healthcheck!"
        }

        healthcheck_message = format_syslog_message(healthcheck_event, kata_ip_address)
        writer.write(healthcheck_message.encode('utf-8') + b'\n')
        await writer.drain()
        logging.debug(f"Отправлено healthcheck-сообщение c KATA {kata_ip_address} на syslog-сервер.")

        logging.info(f"Все события c KATA {kata_ip_address} отправлены на порт {SYSLOG_PORT}/TCP брокера.")

        writer.close()
        await writer.wait_closed()

    except Exception as e:
        logging.error(f"Ошибка при отправке Syslog-сообщений c KATA {kata_ip_address}: {e}")


async def kata_async_request(session, kata_instance: dict):
    """
    Асинхронно обрабатывает одну инсталляцию KATA, запрашивая события.

    Parameters:
        session (aiohttp.ClientSession): Асинхронная сессия для HTTP-запросов.
        kata_instance (dict): Словарь с данными об инсталляции KATA (IP-адрес и UUID).
    """
    await fetch_events(session, kata_instance)


async def main():
    """
    Создание тасок для асинхронных запросов.
    """
    async with aiohttp.ClientSession() as session:
        tasks = [kata_async_request(session, instance) for instance in KATA_INSTANCES]
        await asyncio.gather(*tasks)


if __name__ == "__main__":
    if not os.path.exists(SERVICE_PATH) or not os.path.getsize(SERVICE_PATH) > 0:
        # Проверка на наличие сервиса
        kata_service_creator()
    else:
        logging.debug(f"Сервис kata_api создан по пути {SERVICE_PATH}.")

    if not os.path.exists(TLS_CERTIFICATE) or not os.path.exists(PRIVATE_KEY):
        # Проверка на наличие сертификата и ключа
        generating_tls_certificate()
    else:
        logging.debug("TLS сертификат и приватный ключ обнаружены.")

    asyncio.run(main())

    logging.info("Скрипт успешно завершил свою работу.")
    sys.exit(0)
