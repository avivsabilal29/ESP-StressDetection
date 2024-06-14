import serial

# Inisialisasi Serial
ser = serial.Serial('COM9', 9600)  # Ganti 'COM3' dengan port yang sesuai pada laptop Anda

def read_rs485():
    while True:
        if ser.in_waiting > 0:
            data = ser.readline().decode('utf-8').rstrip()
            print(f"Received data: {data}")

if __name__ == "__main__":
    try:
        read_rs485()
    except KeyboardInterrupt:
        ser.close()
        print("Serial connection closed")
