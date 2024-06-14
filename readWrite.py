import serial
import requests
import threading
import time

# Inisialisasi port serial (sesuaikan dengan port yang digunakan)
wemos_port = "COM5"
baud = 115200
ser = serial.Serial(wemos_port, baud)


# Variabel untuk menyimpan nilai BPM dan suhu
bpm_value = 0
temperature_value = 0
vpin1 = "v1"
vpin2 = "v2"


# Fungsi untuk membaca data dari serial dan memperbarui variabel BPM dan suhu
def read_serial():
    global bpm_value, temperature_value
    while True:
        data = ser.readline().decode().strip()
        if data:
            if data.startswith("BPM="):
                bpm = float(data.split('=')[1])
                if bpm != 0:  # Memastikan nilai BPM tidak nol sebelum memperbarui variabel
                    bpm_value = bpm
            elif "Temperature:" in data:
                temperature = float(data.split(':')[1])
                if temperature != 0:  # Memastikan nilai suhu tidak nol sebelum memperbarui variabel
                    temperature_value = temperature

# Fungsi untuk mengirimkan data BPM dan suhu melalui HTTP
def send_data():
    while True:
        global bpm_value, temperature_value
        try:
            # Kirim hanya jika nilai BPM dan suhu bukan nol
            if bpm_value != 0 and temperature_value != 0:
                # URL untuk mengirimkan permintaan GET
                url = "https://blynk.cloud/external/api/update"
                # Token Blynk Anda
                token = "tSC36UjLdKgiFcvJPLzKHFZP2YtNTwph"
                # Mengirim dua permintaan GET secara bersamaan
                response1 = requests.get(f"{url}?token={token}&{vpin1}={temperature_value}")
                response2 = requests.get(f"{url}?token={token}&{vpin2}={bpm_value}")
                # Memeriksa status respons
                if response1.status_code == 200 and response2.status_code == 200:
                    print("Data berhasil dikirim.")
                else:
                    print("Gagal mengirim data.")
        except Exception as e:
            print("Terjadi kesalahan:", str(e))
        time.sleep(5)  # Mengirim data setiap 5 detik

# Thread untuk membaca data dari serial
serial_thread = threading.Thread(target=read_serial)
serial_thread.daemon = True
serial_thread.start()

# Thread untuk mengirimkan data melalui HTTP
http_thread = threading.Thread(target=send_data)
http_thread.daemon = True
http_thread.start()

# Menunggu kedua thread selesai sebelum keluar dari program
serial_thread.join()
http_thread.join()

# Tutup koneksi port serial
ser.close()
