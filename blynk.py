import requests
import random
import time

vpin1 = "v1"
vpin2 = "v2"

# Fungsi untuk mengirim permintaan GET dengan nilai acak
def send_random_value(url, token, pin):
    # Membuat nilai acak antara 0 dan 100
    random_value = random.randint(0, 100)
    # Membuat URL dengan token dan nilai acak
    request_url = f"{url}?token={token}&{pin}={random_value}"
    # Mengirim permintaan GET
    response = requests.get(request_url)
    # Mengecek status respons
    if response.status_code == 200:
        print(f"Nilai {random_value} berhasil dikirim.")
    else:
        print("Gagal mengirim permintaan.")

# URL untuk mengirimkan permintaan GET
url = "https://blynk.cloud/external/api/update"
# Token Blynk Anda
token = "tSC36UjLdKgiFcvJPLzKHFZP2YtNTwph"

# Loop untuk mengirimkan permintaan secara berulang-ulang
while True:
    send_random_value(url, token, vpin1)
    send_random_value(url, token, vpin2)
    # Menunggu 5 detik sebelum mengirim permintaan berikutnya
    time.sleep(5)
