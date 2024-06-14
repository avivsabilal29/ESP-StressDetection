#include <Wire.h>
#include <MAX30100_PulseOximeter.h>
#include <OneWire.h>
#include <DallasTemperature.h>
#include <ESP8266WiFi.h>
#include <BlynkSimpleEsp8266.h>

#define BLYNK_TEMPLATE_ID "TMPL6E5tK3Mje"
#define BLYNK_TEMPLATE_NAME "Implementasi Alat Pendeteksi Stres berbasis IoT"
#define BLYNK_AUTH_TOKEN "r2TNE81EDWxKYukq1avaJqnUT6YVy1WL"

#define REPORTING_PERIOD_MS 1000
#define ONE_WIRE_BUS 0
PulseOximeter pox;
OneWire oneWire(ONE_WIRE_BUS);
DallasTemperature sensors(&oneWire);
uint32_t tsLastReport = 0;

char ssid[] = "KONTRAKAN ALUMNI";
char pass[] = "TMUA1443H";

BlynkTimer timer;

void setup() {
  Serial.begin(115200);
  Blynk.begin(BLYNK_AUTH_TOKEN, ssid, pass);
  sensors.begin();
  pox.begin();
  pox.setIRLedCurrent(MAX30100_LED_CURR_7_6MA);
  timer.setInterval(1000L, myTimerEvent);
}

void loop() {
  Blynk.run();
  timer.run();
}

void myTimerEvent() {
  float heartRate = pox.getHeartRate();
  sensors.requestTemperatures();
  float temp = sensors.getTempCByIndex(0);
  Blynk.virtualWrite(V1, temp);
  Blynk.virtualWrite(V2, heartRate);
}
