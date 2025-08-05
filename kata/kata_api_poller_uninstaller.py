import os
import subprocess
import shutil

SERVICE_NAME = "kata_api.service"
SERVICE_PATH = "/etc/systemd/system/kata_api.service"
PROGRAM_PATH = "/opt/kata/"

def stop_and_remove_service():
    """Останавливает и удаляет systemd-сервис KATA."""
    subprocess.run(["sudo", "systemctl", "stop", SERVICE_NAME], check=False)
    subprocess.run(["sudo", "systemctl", "disable", SERVICE_NAME], check=False)
    if os.path.exists(SERVICE_PATH):
        os.remove(SERVICE_PATH)
    subprocess.run(["sudo", "systemctl", "daemon-reload"], check=False)
    subprocess.run(["sudo", "systemctl", "reset-failed"], check=False)
    print(f"Сервис {SERVICE_NAME} остановлен и удалён.")

def remove_kata_directory():
    """Удаляет каталог /opt/kata и всё его содержимое."""
    if os.path.exists(PROGRAM_PATH):
        shutil.rmtree(PROGRAM_PATH)
        print(f"Каталог {PROGRAM_PATH} полностью удалён.")
    else:
        print(f"Каталог {PROGRAM_PATH} не найден.")


if __name__ == "__main__":
    stop_and_remove_service()
    remove_kata_directory()
