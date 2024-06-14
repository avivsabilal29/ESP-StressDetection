#include <Wire.h>
#include "MAX30105.h"
#include "heartRate.h"
#include <OneWire.h>
#include <DallasTemperature.h>

// Heart rate sensor variables
MAX30105 particleSensor;
const byte RATE_SIZE = 4; //Increase this for more averaging. 4 is good.
byte rates[RATE_SIZE]; //Array of heart rates
byte rateSpot = 0;
long lastBeat = 0; //Time at which the last beat occurred
float beatsPerMinute;
int beatAvg;
const unsigned long interval1 = 10; // interval untuk fungsi pertama (dalam milidetik)
const unsigned long interval2 = 2000;  // interval untuk fungsi kedua (dalam milidetik)
unsigned long previousMillis1 = 0;   // variabel untuk menyimpan waktu terakhir fungsi pertama dijalankan
unsigned long previousMillis2 = 0;   // variabel untuk menyimpan waktu terakhir fungsi kedua dijalankan

// Temperature sensor variables
#define ONE_WIRE_BUS 0
OneWire oneWire(ONE_WIRE_BUS);
DallasTemperature sensors(&oneWire);

void setup() {
  Serial.begin(115200);
  Serial.println("Initializing...");

  // Initialize heart rate sensor
  if (!particleSensor.begin(Wire, I2C_SPEED_FAST)) {
    Serial.println("MAX30102 was not found. Please check wiring/power.");
    while (1);
  }
  particleSensor.setup(); //Configure sensor with default settings
  particleSensor.setPulseAmplitudeRed(0x0A); //Turn Red LED to low to indicate sensor is running
  particleSensor.setPulseAmplitudeGreen(0); //Turn off Green LED

  // Initialize temperature sensor
  sensors.begin();
}

void loop() {
  // Non-blocking code, nothing to do here
  unsigned long currentMillis = millis(); // mendapatkan waktu saat ini

  // Menjalankan fungsi pertama setiap interval1 milidetik
  if (currentMillis - previousMillis1 >= interval1) {
    // Update waktu terakhir fungsi pertama dijalankan
    previousMillis1 = currentMillis;

    // Panggil fungsi pertama di sini
    readHeartRate();
  }

  // Menjalankan fungsi kedua setiap interval2 milidetik
  if (currentMillis - previousMillis2 >= interval2) {
    // Update waktu terakhir fungsi kedua dijalankan
    previousMillis2 = currentMillis;

    // Panggil fungsi kedua di sini
    readTemperatureBody();
  }
}

// Heart rate sensor reading function
void readHeartRate() {
  long irValue = particleSensor.getIR();
  if (checkForBeat(irValue)) {
    //We sensed a beat!
    long delta = millis() - lastBeat;
    lastBeat = millis();

    beatsPerMinute = 60 / (delta / 1000.0);

    if (beatsPerMinute < 255 && beatsPerMinute > 20) {
      rates[rateSpot++] = (byte)beatsPerMinute; //Store this reading in the array
      rateSpot %= RATE_SIZE; //Wrap variable

      //Take average of readings
      beatAvg = 0;
      for (byte x = 0; x < RATE_SIZE; x++)
        beatAvg += rates[x];
      beatAvg /= RATE_SIZE;
    }
  }

  Serial.print("IR=");
  Serial.println(irValue);
  Serial.print("BPM=");
  Serial.println(beatsPerMinute);
  Serial.print("Avg BPM=");
  Serial.println(beatAvg);
  //  if (irValue < 50000)
  //    Serial.print(" No finger?");
  //  Serial.println();
}

// Temperature sensor reading function
void readTemperatureBody() {
  sensors.requestTemperatures();

  // Print the temperature in Celsius and Fahrenheit
  Serial.print("Temperature: ");
  Serial.println(sensors.getTempCByIndex(0));
  //  Serial.print((char)176);
  //  Serial.print("C | ");
  //  Serial.print((sensors.getTempCByIndex(0) * 9.0) / 5.0 + 32.0);
  //  Serial.print((char)176);
  //  Serial.println("F");
}
