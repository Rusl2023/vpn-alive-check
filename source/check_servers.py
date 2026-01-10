import socket
import requests
from urllib.parse import urlparse

SOURCE_URL = "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/26.txt"
OUTPUT_FILE = "githubmirror/26_alive.txt"
TCP_TIMEOUT = 2      # секунды для TCP соединения
HTTP_TIMEOUT = 2     # секунды для HTTP запроса


def tcp_check(host, port):
    """Проверяем, открыта ли TCP порта на сервере"""
    try:
        with socket.create_connection((host, port), timeout=TCP_TIMEOUT):
            return True
    except:
        return False


def http_test(proxy_url):
    """Проверка HTTP через прокси (если vless/vmess/trojan поддерживает)"""
    try:
        proxies = {
            "http": proxy_url,
            "https": proxy_url
        }
        r = requests.get("https://www.google.com/generate_204", proxies=proxies, timeout=HTTP_TIMEOUT, verify=False)
        return r.status_code == 204
    except:
        return False


# 1️⃣ Скачиваем список серверов
try:
    resp = requests.get(SOURCE_URL, timeout=5)
    resp.raise_for_status()
    servers = resp.text.splitlines()
except Exception as e:
    print(f"Не удалось скачать список серверов: {e}")
    servers = []

alive = []

for line in servers:
    line = line.strip()
    if not line:
        continue

    parsed = urlparse(line)
    host = parsed.hostname
    port = parsed.port or 443  # если порт не указан, пробуем 443

    if not host:
        continue

    # 2️⃣ TCP проверка
    if not tcp_check(host, port):
        print(f"[TCP FAIL] {host}:{port}")
        continue

    # 3️⃣ HTTP тест (необязательный)
    if http_test(line):
        alive.append(line)
        print(f"[ALIVE] {line}")
    else:
        print(f"[HTTP FAIL] {line}")


# 4️⃣ Сохраняем результат
with open(OUTPUT_FILE, "w") as f:
    f.write("\n".join(alive))

print(f"\n✅ Всего живых серверов: {len(alive)}")
