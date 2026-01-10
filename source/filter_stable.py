import os
import socket
from urllib.parse import urlparse

INPUT_FILE = os.environ.get("INPUT_FILE", "githubmirror/26_alive.txt")
OUTPUT_FILE = os.environ.get("OUTPUT_FILE", "githubmirror/26_stable.txt")
MAX_PING = int(os.environ.get("MAX_PING", 600))

alive_by_country = {}

def check_tcp(host, port, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except:
        return False

with open(INPUT_FILE, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            url = urlparse(line)
            host = url.hostname
            port = url.port or 443

            # читаем ping из строки, если есть "ping XXX"
            if "ping" in line:
                ping_str = line.split("ping")[-1].split()[0]
                ping_val = int(ping_str)
            else:
                ping_val = 9999  # если нет, считаем плохим

            if ping_val > MAX_PING:
                continue

            if not check_tcp(host, port):
                continue

            # определяем страну
            country = "Unknown"
            for part in line.split():
                if part.startswith("🇦") or part.startswith("🇧") or part.startswith("🇨") \
                   or part.startswith("RU") or part.startswith("US") or part.startswith("NL") \
                   or part.startswith("FI") or part.startswith("PL") or part.startswith("DE"):
                    country = part
                    break

            if country not in alive_by_country or ping_val < alive_by_country[country][1]:
                alive_by_country[country] = (line, ping_val)
        except:
            continue

# сохраняем результат
os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    for link, ping in sorted(alive_by_country.values(), key=lambda x: x[1]):
        f.write(link + "\n")

print(f"Stable servers saved: {len(alive_by_country)}")

with open(os.environ.get("GITHUB_OUTPUT", "/dev/null"), "a") as out:
    out.write(f"count={len(alive_by_country)}\n")
