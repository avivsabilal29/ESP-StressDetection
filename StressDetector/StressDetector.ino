#include <ESP8266WiFi.h>
#include <BlynkSimpleEsp8266.h>
#include <OneWire.h>
#include <DallasTemperature.h>
#include <Wire.h>
#include <Adafruit_Sensor.h>
#include <Adafruit_MAX30105.h>
#include <heartRate.h>

// Pengaturan WiFi
char auth[] = "YourAuthToken";
char ssid[] = "YourNetworkName";
char pass[] = "YourPassword";

// Pengaturan pin
#define ONE_WIRE_BUS D2 // Pin untuk sensor DS18B20
#define MAX30102_INT D1 // Pin interrupt untuk MAX30102

// Setup sensor suhu
OneWire oneWire(ONE_WIRE_BUS);
DallasTemperature sensors(&oneWire);

// Setup sensor MAX30102
Adafruit_MAX30105 max30102;

// Variabel untuk menyimpan data sensor
float temperature = 0.0;
int heartRate = 0;
int GSR = 0; // Variabel ini perlu diupdate sesuai dengan input sensor GSR

void setup()
{
    Serial.begin(115200);
    Blynk.begin(auth, ssid, pass);

    sensors.begin();
    if (!max30102.begin())
    {
        Serial.println("Could not find a valid MAX30102 sensor, check wiring!");
        while (1)
            ;
    }

    // Konfigurasi sensor MAX30102
    max30102.setup();
}

void loop()
{
    Blynk.run();

    sensors.requestTemperatures();
    temperature = sensors.getTempCByIndex(0);

    // Baca data dari MAX30102
    long irValue = max30102.getIR();
    if (checkForBeat(irValue) == true)
    {
        long delta = millis() - lastBeat;
        lastBeat = millis();
        heartRate = 60 / (delta / 1000.0);
    }

    // Analisis klasifikasi menggunakan metode k-NN
    classifyStressLevel(GSR, heartRate, temperature);

    // Kirim data ke Blynk
    Blynk.virtualWrite(V1, temperature);
    Blynk.virtualWrite(V2, heartRate);
    Blynk.virtualWrite(V3, GSR);
}

// Fungsi untuk klasifikasi tingkat stres
void classifyStressLevel(int GSR, int HR, float Temp)
{
    if (GSR < 2 && HR >= 60 && HR <= 70 && Temp >= 36 && Temp <= 37)
    {
        Serial.println("Relaxed");
    }
    else if (GSR >= 2 && GSR <= 4 && HR > 70 && HR <= 90 && Temp < 36 && Temp >= 35)
    {
        Serial.println("Calm");
    }
    else if (GSR > 4 && GSR <= 6 && HR > 90 && HR <= 100 && Temp < 35 && Temp >= 33)
    {
        Serial.println("Tense");
    }
    else if (GSR > 6 && HR > 100 && Temp < 33)
    {
        Serial.println("Stressed");
    }
    else
    {
        Serial.println("Data not sufficient for classification");
    }
}
