#include <Wire.h>
#include "RTClib.h"
#include <SPI.h>
#include <SD.h>
#include <DHT.h>

//variables

int sensorNumber = 2;

//initialization

RTC_DS1307 rtc;
uint32_t current_time = 0; // keep current time (for checking difference to store data)
File myFile;
const char filename[20];
bool headerWritten = false; // Flag to check if the header has been written
#define DHTPIN 7
#define DHTTYPE DHT22
DHT dht(DHTPIN, DHTTYPE);
float temperatureC;
float humidity;

// Create string of date and time
String datetime(const DateTime& now, bool dateonly = false) {
    char dateTimeStr[20];
    
    if (dateonly) {
        snprintf(dateTimeStr, sizeof(dateTimeStr), "%04d%02d%02d.csv", now.year(), now.month(), now.day());
    } else {
        snprintf(dateTimeStr, sizeof(dateTimeStr), "%02d.%02d.%04d;%02d:%02d:%02d", now.day(), now.month(), now.year(), now.hour(), now.minute(), now.second());
    }
    
    return String(dateTimeStr);
}

void writeDataToFile(const DateTime& now, float temperature, float humidity){
  if(!myFile){
    myFile = SD.open(filename, FILE_WRITE);
  }
  String tempStr = String(temperatureC, 2);
  String humidityStr = String(humidity, 2);
  myFile.println(datetime(now) + ";" + tempStr + ";" + humidityStr);
  myFile.flush(); // Ensure data is written to the file
  //let the LED blink for 5 milliseconds
  blinkLED();
}

void setup() {
  pinMode(LED_BUILTIN, OUTPUT); //initialize the TX-LED from the arduino
  Serial.begin(9600);
  
  if (!rtc.begin()) {
    Serial.println("Couldn't find RTC");
    while (1);
  }
  
  if (Serial){
      if (!rtc.isrunning()) {
          Serial.println("RTC is NOT running! Setting the RTC to the compile time.");
          // Reinitialize the RTC to compile time if it's not running
          rtc.adjust(DateTime(F(__DATE__), F(__TIME__))); 
          Serial.println("RTC adjusted to compile time!");
      } else {
          // Check if the current RTC time is correct
          DateTime now = rtc.now();
          DateTime compileTime = DateTime(F(__DATE__), F(__TIME__));

          // Calculate the date and time for yesterday
          DateTime yesterday = compileTime - TimeSpan(1, 0, 0, 0);
          
          if (now.unixtime() < yesterday.unixtime()) {
              // Adjust the RTC if the current time is incorrect
              Serial.println("RTC time is incorrect. Adjusting the RTC to compile time.");
              rtc.adjust(compileTime);
              Serial.println("RTC adjusted to compile time!");
          } else {
              Serial.println("RTC is running and time is correct.");
          }
      }
  }
  dht.begin();

  // next section used to create a new headline on reconnecting and append to existing file without user input
  
  snprintf(filename, sizeof(filename), "Sensor%02d.csv", sensorNumber); // Format filename as SensorXX.csv
  
  if (SD.begin(5)) {
    if (!SD.exists(filename)) {
      myFile = SD.open(filename, FILE_WRITE);
      if (myFile) {
        myFile.println("Date;Time;Temperature (C);Humidity (%)"); // Header of CSV
        // myFile.close();
        Serial.println("New file created with header.");
      }
    } else {
      myFile = SD.open(filename, FILE_WRITE);
      if (myFile) {
        myFile.println("Date;Time;Temperature (C);Humidity (%)"); // Header of CSV
        // myFile.close();
        Serial.println("New header added to existing file.");
      }
    }
  } else {
    Serial.println("SD card NOT running!");
    while (1);
  }
  
}

//let the LED-blink everytime the arduino retrieves and writes the data into the SD
void blinkLED() {
  digitalWrite(LED_BUILTIN, HIGH); // Turn the LED on
  delay(500);                      // Wait for 500 milliseconds
  digitalWrite(LED_BUILTIN, LOW);  // Turn the LED off
  delay(100);                      // Wait for 100 milliseconds
  Serial.println("writing Data to SD...");
}

void loop() {
  DateTime now = rtc.now(); // Retrieves the current date and time from the RTC

  // Check if the seconds are a multiple of 10
  if (now.second() % 5 == 0) { // every 5 seconds at exact multiples of 10 (e.g., 10, 20, 30, etc.)
    // Avoid multiple writes within the same second
    if (now.unixtime() != current_time) {
      temperatureC = dht.readTemperature();
      humidity = dht.readHumidity();

      // Write data to file and let TX-LED blink for 5 milliseconds
      writeDataToFile(now, temperatureC, humidity);

      // Update the current_time to the latest measurement time
      current_time = now.unixtime();
    }
}
}
  
