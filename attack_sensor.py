import requests

url = "http://10.31.37.6:5000/api/sensor_reading"

fake_data = {
    "device_index": 0,
    "sensor_id": "FAKE_SENSOR",
    "token": "WRONG_TOKEN",
    "temperature": 99,
    "humidity": 5
}

print("Launching fake sensor attack...")
print("Target:", url)

response = requests.post(url, json=fake_data, timeout=5)

print("Status Code:", response.status_code)
print("Response:")
print(response.text)