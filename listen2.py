import serial

# Inisialisasi port serial (sesuaikan dengan port yang digunakan)
wemos_port = "COM7"
baud = 9600

ser = serial.Serial(wemos_port, baud)
print("Connected to Wemos port " + wemos_port)

try:
    while True:
        try:
            # Baca data dari port serial
            data = ser.readline().decode('utf-8').rstrip()
            if data:
                print(data)
        except UnicodeDecodeError:
            print("UnicodeDecodeError: Cannot decode data:", ser.readline())
            continue
except KeyboardInterrupt:
    print("Interrupted by user")

# Tutup koneksi port serial
ser.close()


from pymodbus.client.sync import ModbusSerialClient
import datetime
import time
BAT_VOLTAGE = 0x331A
BAT_TEMP = 0x3110


while True:
    try:
        scc = ModbusSerialClient(method="rtu", port="/dev/ttyS0", baudrate=115200)
        batt = scc.read_input_registers(BAT_VOLTAGE, 1, unit=1)
        battVoltage = batt.registers[0]/100
        print(datetime.datetime.now())
        print("Battery Voltage :", battVoltage, "V")
        time.sleep(0.5)
        batt = scc.read_input_registers(BAT_TEMP, 1, unit=1)
        battTemp = batt.registers[0]/100
        print("Battery Temperature :", battTemp, "C")
        print("")
    except Exception as e:
        print(e)    
    time.sleep(2)
