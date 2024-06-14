#include <Wire.h>
#include "MAX30105.h"
#include "heartRate.h"
#include <OneWire.h>
#include <DallasTemperature.h>
#define ONE_WIRE_BUS 0

MAX30105 particleSensor;
const byte RATE_SIZE = 4; //Increase this for more averaging. 4 is good.
byte rates[RATE_SIZE]; //Array of heart rates
byte rateSpot = 0;
long lastBeat = 0; //Time at which the last beat occurred

String dataLabel1 = "IR_Value";
String dataLabel2 = "BPM_Value";
String dataLabel3 = "BPM_Average";
bool label = true;

OneWire oneWire(ONE_WIRE_BUS);
DallasTemperature sensors(&oneWire);

float beatsPerMinute;
int beatAvg;


void setup() {
  Serial.begin(115200);
  heartSetup();
  tempSetup();
}

void loop() {
  heartRate();
//  readTemp();
}
