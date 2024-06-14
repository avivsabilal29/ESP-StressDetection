import serial
import time
# Konfigurasi port serial
port = 'COM7'  # Ganti dengan port USB RS485 Anda
baudrate = 9600  # Ganti dengan baud rate yang sesuai
timeout = 1  # Ganti dengan timeout yang sesuai

# Buka port serial
ser = serial.Serial(port=port, baudrate=baudrate, timeout=timeout)

# Masukkan angka integer yang ingin dikirim
data = 'hello aviv'
while True:
    # Kirim angka integer ke Raspberry Pi
    print(f'data sended: {ser.write(data.encode())}')
    time.sleep(1)

# Tutup port serial
ser.close()