import requests #to send http requests
url = "http://127.0.0.1:8000"
for i in range(15):
    requests.post(
        url,
        data={
            "username": "admin",
            "password": f"wrong{i}"
        }
    )
print("Brute Force Initialized!")