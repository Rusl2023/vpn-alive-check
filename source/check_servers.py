import subprocess
import re
import requests
from urllib.parse import urlparse

SOURCE_URL = "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/26.txt"
PING_LIMIT = 400


def ping(host):
    try:
        out = subprocess.check_output(
            ["ping", "-c", "2", "-W", "1", host],
            stderr=subprocess.DEVNULL,
            text=True
        )
        m = re.search(r"= [\d\.]+/([\d\.]+)/", out)
        return float(m.group(1)) if m else 9999
    except:
        return 9999


def http_test(proxy):
    try:
        r = requests.get(
            "https://www.google.com/generate_204",
            proxies={"http": proxy, "https": proxy},
            timeout=8,
            verify=False
        )
        return r.status_code == 204
    except:
        return False


# 🔽 Скачиваем актуальный 26.txt
resp = requests.get(SOURCE_URL, timeout=15)
resp.raise_for_status()
lines = resp.text.splitlines()

alive = []

for line in lines:
    line = line.strip()
    if not line:
        continue

    host = urlparse(line).hostname
    if not host:
        continue

    if ping(host) <= PING_LIMIT and http_test(line):
        alive.append(line)

# 🔽 Сохраняем РЕЗУЛЬТАТ у себя
with open("githubmirror/26_alive.txt", "w") as f:
    f.write("\n".join(alive))
