import serial

wemos_port = "COM7"
baud = 115200
fileName= "heartRate.csv"
samples = 10000
print_labels = False

ser = serial.Serial(wemos_port, baud)
print("connected to wemos port" + wemos_port)
file = open(fileName, "a")
print("creat File")

line = 0

while line <= samples:
    if print_labels:
        if line ==0:
            print("Printing colom Header")
        else:
            print("line" + str(line) + ": Writing.....")
    getData = str(ser.readline())
    data = getData[0:][:-2]
    print(data)

    file = open(fileName, "a")
    file.write(data + "\n")
    line = line+1
print("Data Collecting Complete")