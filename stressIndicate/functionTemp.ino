void tempSetup() {
  sensors.begin();
}

void readTemp() {
    sensors.requestTemperatures();
    float temp = sensors.getTempCByIndex(0);
    Serial.print("Temperature: ");
    Serial.print(temp);
    Serial.print((char)176);//shows degrees character
    Serial.println("C  |  ");
    Serial.println("---------");
}
