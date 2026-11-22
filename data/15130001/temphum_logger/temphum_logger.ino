/*
  ============================================================
                     MEDIGUARD AI
            FINAL ENHANCED ESP32 FIRMWARE
  ============================================================

  FINAL GPIO MAP

  DS18B20 DATA       -> GPIO 13
  DHT22 DATA         -> GPIO 26

  OLED + RTC SDA     -> GPIO 21
  OLED + RTC SCL     -> GPIO 22

  GREEN LED          -> GPIO 16
  YELLOW LED         -> GPIO 17
  ORANGE LED         -> GPIO 18
  RED LED            -> GPIO 19
  BLUE LED           -> GPIO 23

  MicroSD:
  CS                 -> GPIO 32
  SCK                -> GPIO 14
  MOSI               -> GPIO 25
  MISO               -> GPIO 27

  Optional buzzer    -> GPIO 33

  ------------------------------------------------------------
  LED MEANINGS

  GREEN  = Normal environment
  YELLOW = Environmental warning
  ORANGE = Sensor / hardware / API problem
  RED    = Critical environment

  RED BLINKING = Cybersecurity alert

  BLUE   = Wi-Fi / Flask communication failure

  ------------------------------------------------------------
  TEMPERATURE RULES

  NORMAL:
  2C <= temperature <= 8C

  WARNING:
  temperature < 2C

  OR

  8C < temperature < 13C

  CRITICAL:
  temperature >= 13C

  ============================================================
*/

#include <WiFi.h>
#include <HTTPClient.h>

#include <Wire.h>

#include <OneWire.h>
#include <DallasTemperature.h>

#include <DHT.h>

#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

#include <RTClib.h>

#include <SPI.h>
#include <SD.h>

#include "mbedtls/md.h"
#include "esp_system.h"
#include "secrets.h"

// ============================================================
// USER SETTINGS
// ============================================================

// Flask computer IP
const char* SERVER_BASE_URL =
  "http://192.168.100.23:5000";


// Existing MediGuard sensor identity
const char* SENSOR_ID =
  "ESP32_ROOM_1";


// ============================================================
// GPIO PINS
// ============================================================

#define DS18B20_PIN 13
#define DHT_PIN     26

#define GREEN_LED   16
#define YELLOW_LED  17
#define ORANGE_LED  18
#define RED_LED     19
#define BLUE_LED    23

#define SDA_PIN     21
#define SCL_PIN     22

#define SD_SCK      14
#define SD_MOSI     25
#define SD_MISO     27
#define SD_CS       32

#define BUZZER_PIN  33


// ============================================================
// OPTIONAL BUZZER
// ============================================================

// Keep disabled for now

#define ENABLE_BUZZER 0


// ============================================================
// DHT22
// ============================================================

#define DHT_TYPE DHT22

DHT dht(
  DHT_PIN,
  DHT_TYPE
);


// ============================================================
// DS18B20
// ============================================================

OneWire oneWire(
  DS18B20_PIN
);

DallasTemperature ds18b20(
  &oneWire
);


// ============================================================
// OLED
// ============================================================

#define SCREEN_WIDTH  128
#define SCREEN_HEIGHT 32

#define OLED_ADDRESS  0x3C
#define OLED_RESET    -1

Adafruit_SSD1306 display(
  SCREEN_WIDTH,
  SCREEN_HEIGHT,
  &Wire,
  OLED_RESET
);


// ============================================================
// RTC
// ============================================================

RTC_DS3231 rtc;


// ============================================================
// MICROSD
// ============================================================

SPIClass sdSPI(VSPI);


// ============================================================
// SENSOR VALUES
// ============================================================

float temperature = NAN;

float humidity = NAN;

float dhtTemperature = NAN;


// ============================================================
// SYSTEM STATES
// ============================================================

String environmentStatus =
  "NO DATA";

String rtcStatus =
  "STARTING";

String sdBackupStatus =
  "SD_MISSING";

bool oledOK = false;

bool rtcOK = false;

bool sdOK = false;

bool sensorFailure = true;

bool communicationFailure = true;

bool apiRejected = false;

bool cyberAlert = false;

bool ntpSynced = false;


// ============================================================
// BUZZER STATE
// ============================================================

bool issueAlreadyBeeped = false;


// ============================================================
// TIMERS
// ============================================================

unsigned long lastSensorRead = 0;

unsigned long lastServerSend = 0;

unsigned long lastDisplayUpdate = 0;

unsigned long lastWiFiRetry = 0;

unsigned long lastNtpRetry = 0;


const unsigned long SENSOR_INTERVAL =
  2000;

const unsigned long SERVER_INTERVAL =
  5000;

const unsigned long DISPLAY_INTERVAL =
  250;

const unsigned long WIFI_RETRY =
  10000;

const unsigned long NTP_RETRY =
  60000;


// ============================================================
// SERVER URLS
// ============================================================

String sensorURL() {

  return String(SERVER_BASE_URL) +
         "/api/sensor_reading";
}


String hardwareStatusURL() {

  return String(SERVER_BASE_URL) +
         "/api/hardware_status";
}


// ============================================================
// ENVIRONMENT CLASSIFICATION
// ============================================================

String classifyEnvironment(
  float temp,
  float hum
) {

  // ----------------------------------
  // Temperature critical
  // ----------------------------------

  if (temp >= 13.0) {

    return "CRITICAL";
  }


  // ----------------------------------
  // Very abnormal humidity
  // ----------------------------------

  if (
    hum < 20.0 ||
    hum > 90.0
  ) {

    return "CRITICAL";
  }


  // ----------------------------------
  // Temperature warning
  // ----------------------------------

  if (
    temp < 2.0 ||
    (
      temp > 8.0 &&
      temp < 13.0
    )
  ) {

    return "WARNING";
  }


  // ----------------------------------
  // Humidity warning
  // ----------------------------------

  if (
    hum < 30.0 ||
    hum > 80.0
  ) {

    return "WARNING";
  }


  return "NORMAL";
}


// ============================================================
// READ SENSORS
// ============================================================

void readSensors() {

  // ----------------------------------------------------------
  // DS18B20
  // Primary storage temperature
  // ----------------------------------------------------------

  ds18b20.requestTemperatures();

  float newTemperature =
    ds18b20.getTempCByIndex(0);


  // ----------------------------------------------------------
  // DHT22
  // ----------------------------------------------------------

  float newHumidity =
    dht.readHumidity();

  float newDhtTemperature =
    dht.readTemperature();


  // ----------------------------------------------------------
  // Validate DS18B20
  // ----------------------------------------------------------

  bool dsFailed = false;

  if (
    newTemperature ==
      DEVICE_DISCONNECTED_C ||

    newTemperature < -55.0 ||

    newTemperature > 125.0
  ) {

    dsFailed = true;
  }


  // ----------------------------------------------------------
  // Validate DHT22
  // ----------------------------------------------------------

  bool dhtFailed =
    isnan(newHumidity) ||
    isnan(newDhtTemperature);


  // ----------------------------------------------------------
  // Sensor failure
  // ----------------------------------------------------------

  if (
    dsFailed ||
    dhtFailed
  ) {

    sensorFailure = true;

    environmentStatus =
      "SENSOR FAIL";

    Serial.println(
      "[HARDWARE] SENSOR FAILURE"
    );

    return;
  }


  // ----------------------------------------------------------
  // Sensor readings OK
  // ----------------------------------------------------------

  sensorFailure = false;

  temperature =
    newTemperature;

  humidity =
    newHumidity;

  dhtTemperature =
    newDhtTemperature;


  environmentStatus =
    classifyEnvironment(
      temperature,
      humidity
    );


  // ----------------------------------------------------------
  // Serial output
  // ----------------------------------------------------------

  Serial.print(
    "DS18B20: "
  );

  Serial.print(
    temperature,
    2
  );

  Serial.print(
    " C | DHT22: "
  );

  Serial.print(
    dhtTemperature,
    2
  );

  Serial.print(
    " C | Humidity: "
  );

  Serial.print(
    humidity,
    2
  );

  Serial.print(
    "% | ENV: "
  );

  Serial.println(
    environmentStatus
  );
}


// ============================================================
// WI-FI INITIAL CONNECTION
// ============================================================

void connectWiFi() {

  Serial.println();

  Serial.print(
    "Connecting WiFi"
  );


  WiFi.mode(
    WIFI_STA
  );

  WiFi.setSleep(
    false
  );


  WiFi.begin(
    WIFI_SSID,
    WIFI_PASSWORD
  );


  unsigned long start =
    millis();


  while (
    WiFi.status() !=
      WL_CONNECTED &&

    millis() - start <
      10000
  ) {

    Serial.print(".");

    delay(500);
  }


  Serial.println();


  if (
    WiFi.status() ==
    WL_CONNECTED
  ) {

    Serial.println(
      "WiFi connected"
    );

    Serial.print(
      "ESP32 IP: "
    );

    Serial.println(
      WiFi.localIP()
    );

    communicationFailure =
      false;
  }

  else {

    Serial.println(
      "WiFi unavailable"
    );

    communicationFailure =
      true;
  }
}


// ============================================================
// WIFI RECONNECT
// ============================================================

void maintainWiFi() {

  if (
    WiFi.status() ==
    WL_CONNECTED
  ) {

    return;
  }


  communicationFailure =
    true;


  if (
    millis() -
    lastWiFiRetry <
    WIFI_RETRY
  ) {

    return;
  }


  lastWiFiRetry =
    millis();


  Serial.println(
    "Retrying WiFi..."
  );


  WiFi.disconnect();


  WiFi.begin(
    WIFI_SSID,
    WIFI_PASSWORD
  );
}


// ============================================================
// NTP
// ============================================================

bool syncNTP() {

  if (
    WiFi.status() !=
    WL_CONNECTED
  ) {

    return false;
  }


  Serial.println(
    "Trying NTP synchronization..."
  );


  // UTC
  configTime(
    0,
    0,
    "pool.ntp.org",
    "time.nist.gov"
  );


  unsigned long start =
    millis();


  while (
    millis() - start <
    5000
  ) {

    time_t currentTime =
      time(nullptr);


    if (
      currentTime >
      1700000000
    ) {

      ntpSynced =
        true;


      rtcStatus =
        "NTP_SYNCED";


      Serial.println(
        "NTP synchronized"
      );


      // ------------------------------------------------------
      // Synchronize RTC with UTC NTP time
      // ------------------------------------------------------

      if (rtcOK) {

        rtc.adjust(
          DateTime(
            (uint32_t)
            currentTime
          )
        );
      }


      return true;
    }


    delay(250);
  }


  Serial.println(
    "NTP unavailable - using RTC"
  );


  return false;
}


// ============================================================
// GET VALID TIMESTAMP
// ============================================================

uint32_t getTimestamp() {

  // ----------------------------------------------------------
  // FIRST OPTION:
  // NTP / ESP32 system time
  // ----------------------------------------------------------

  time_t systemTime =
    time(nullptr);


  if (
    systemTime >
    1700000000
  ) {

    rtcStatus =
      "NTP_SYNCED";


    return
      (uint32_t)
      systemTime;
  }


  // ----------------------------------------------------------
  // SECOND OPTION:
  // DS3231 RTC
  //
  // IMPORTANT:
  // We validate the actual RTC date.
  // We do NOT block RTC just because lostPower() was once true.
  // ----------------------------------------------------------

  if (rtcOK) {

    DateTime rtcNow =
      rtc.now();


    bool validRTC =

      rtcNow.year() >= 2025 &&

      rtcNow.year() <= 2035 &&

      rtcNow.month() >= 1 &&

      rtcNow.month() <= 12 &&

      rtcNow.day() >= 1 &&

      rtcNow.day() <= 31;


    if (validRTC) {

      rtcStatus =
        "RTC_FALLBACK";


      return
        rtcNow.unixtime();
    }
  }


  // ----------------------------------------------------------
  // NO VALID TIME SOURCE
  // ----------------------------------------------------------

  rtcStatus =
    "TIME_FAIL";


  return 0;
}


// ============================================================
// GENERATE RANDOM NONCE
// ============================================================

String generateNonce() {

  char nonce[33];


  uint32_t a =
    esp_random();

  uint32_t b =
    esp_random();

  uint32_t c =
    esp_random();

  uint32_t d =
    esp_random();


  snprintf(
    nonce,
    sizeof(nonce),

    "%08lX%08lX%08lX%08lX",

    (unsigned long)a,

    (unsigned long)b,

    (unsigned long)c,

    (unsigned long)d
  );


  return String(nonce);
}


// ============================================================
// HMAC SHA-256
// ============================================================

String generateHMAC(
  float temp,
  float hum,
  uint32_t timestamp,
  String nonce
) {

  // ----------------------------------------------------------
  // Flask expected format:
  //
  // sensor_id|temperature|humidity|timestamp|nonce
  //
  // temperature and humidity MUST use 2 decimals
  // ----------------------------------------------------------

  String tempString =
    String(
      temp,
      2
    );


  String humidityString =
    String(
      hum,
      2
    );


  String message =

    String(SENSOR_ID) +

    "|" +

    tempString +

    "|" +

    humidityString +

    "|" +

    String(timestamp) +

    "|" +

    nonce;


  Serial.print(
    "HMAC message: "
  );

  Serial.println(
    message
  );


  unsigned char hmacResult[32];


  const mbedtls_md_info_t*
    mdInfo =

    mbedtls_md_info_from_type(
      MBEDTLS_MD_SHA256
    );


  mbedtls_md_hmac(

    mdInfo,

    (const unsigned char*)
      MEDIGUARD_HMAC_SECRET,

    strlen(
      MEDIGUARD_HMAC_SECRET
    ),

    (const unsigned char*)
      message.c_str(),

    message.length(),

    hmacResult
  );


  char hexOutput[65];


  for (
    int i = 0;
    i < 32;
    i++
  ) {

    sprintf(

      &hexOutput[
        i * 2
      ],

      "%02x",

      hmacResult[i]
    );
  }


  hexOutput[64] =
    '\0';


  return String(
    hexOutput
  );
}


// ============================================================
// MICROSD INITIALIZATION
// ============================================================

void initializeSD() {

  sdSPI.begin(
    SD_SCK,
    SD_MISO,
    SD_MOSI,
    SD_CS
  );


  if (
    !SD.begin(
      SD_CS,
      sdSPI
    )
  ) {

    sdOK =
      false;


    sdBackupStatus =
      "SD_MISSING";


    Serial.println(
      "MicroSD unavailable"
    );


    return;
  }


  if (
    SD.cardType() ==
    CARD_NONE
  ) {

    sdOK =
      false;


    sdBackupStatus =
      "SD_MISSING";


    Serial.println(
      "No MicroSD card inserted"
    );


    return;
  }


  sdOK =
    true;


  sdBackupStatus =
    "NOT_REQUIRED";


  Serial.println(
    "MicroSD ready"
  );
}


// ============================================================
// SAVE OFFLINE READING
// ============================================================

bool saveOfflineReading(
  uint32_t timestamp
) {

  if (!sdOK) {

    sdBackupStatus =
      "BACKUP_UNAVAILABLE";


    Serial.println(
      "Offline backup unavailable - no SD"
    );


    return false;
  }


  bool newFile =
    !SD.exists(
      "/offline.csv"
    );


  File file =
    SD.open(
      "/offline.csv",
      FILE_APPEND
    );


  if (!file) {

    sdBackupStatus =
      "BACKUP_FAILED";


    Serial.println(
      "SD backup failed"
    );


    return false;
  }


  if (newFile) {

    file.println(
      "timestamp,temperature,humidity,dht22_temperature,status"
    );
  }


  file.print(
    timestamp
  );

  file.print(",");


  file.print(
    temperature,
    2
  );

  file.print(",");


  file.print(
    humidity,
    2
  );

  file.print(",");


  file.print(
    dhtTemperature,
    2
  );

  file.print(",");


  file.println(
    environmentStatus
  );


  file.close();


  sdBackupStatus =
    "BACKUP_SAVED";


  Serial.println(
    "Offline reading saved to SD"
  );


  return true;
}


// ============================================================
// LOCAL ALERT STRING
// ============================================================

String getLocalAlert() {

  if (sensorFailure) {

    return
      "SENSOR_FAILURE";
  }


  if (cyberAlert) {

    return
      "CYBER_ALERT";
  }


  if (apiRejected) {

    return
      "API_REJECTED";
  }


  if (communicationFailure) {

    return
      "OFFLINE";
  }


  return
    environmentStatus;
}


// ============================================================
// BACKEND SECURITY STATUS
// ============================================================

void fetchCyberStatus() {

  if (
    WiFi.status() !=
    WL_CONNECTED
  ) {

    return;
  }


  HTTPClient http;


  http.setTimeout(
    3000
  );


  if (
    !http.begin(
      hardwareStatusURL()
    )
  ) {

    return;
  }


  int code =
    http.GET();


  if (code == 200) {

    String response =
      http.getString();


    // --------------------------------------------------------
    // Check for:
    // "active_cyber_alert": true
    // --------------------------------------------------------

    bool active =

      response.indexOf(
        "\"active_cyber_alert\":true"
      ) >= 0

      ||

      response.indexOf(
        "\"active_cyber_alert\": true"
      ) >= 0;


    cyberAlert =
      active;


    Serial.print(
      "Cyber status: "
    );


    if (cyberAlert) {

      Serial.println(
        "CYBER ALERT"
      );
    }

    else {

      Serial.println(
        "SECURE"
      );
    }
  }


  http.end();
}


// ============================================================
// SEND READING TO FLASK
// ============================================================

void sendToFlask() {

  // ----------------------------------------------------------
  // Never send invalid sensor data
  // ----------------------------------------------------------

  if (sensorFailure) {

    Serial.println(
      "Upload skipped: sensor failure"
    );

    return;
  }


  // ----------------------------------------------------------
  // GET TIMESTAMP
  // ----------------------------------------------------------

  uint32_t timestamp =
    getTimestamp();


  if (
    timestamp == 0
  ) {

    Serial.println(
      "Upload skipped: no valid timestamp"
    );

    return;
  }


  Serial.print(
    "Time source: "
  );

  Serial.println(
    rtcStatus
  );


  // ----------------------------------------------------------
  // WiFi OFFLINE
  // ----------------------------------------------------------

  if (
    WiFi.status() !=
    WL_CONNECTED
  ) {

    communicationFailure =
      true;


    Serial.println(
      "Server upload unavailable: WiFi offline"
    );


    saveOfflineReading(
      timestamp
    );


    return;
  }


  // ----------------------------------------------------------
  // NONCE
  // ----------------------------------------------------------

  String nonce =
    generateNonce();


  // ----------------------------------------------------------
  // SIGNATURE
  // ----------------------------------------------------------

  String signature =
    generateHMAC(

      temperature,

      humidity,

      timestamp,

      nonce
    );


  // ----------------------------------------------------------
  // JSON PAYLOAD
  // ----------------------------------------------------------

  String payload = "{";


  payload +=
    "\"device_index\":0,";


  payload +=
    "\"sensor_id\":\"" +
    String(SENSOR_ID) +
    "\",";


  payload +=
    "\"temperature\":" +
    String(
      temperature,
      2
    ) +
    ",";


  payload +=
    "\"humidity\":" +
    String(
      humidity,
      2
    ) +
    ",";


  payload +=
    "\"timestamp\":" +
    String(timestamp) +
    ",";


  payload +=
    "\"nonce\":\"" +
    nonce +
    "\",";


  payload +=
    "\"signature\":\"" +
    signature +
    "\",";


  payload +=
    "\"hardware_profile\":\"enhanced_v2\",";


  payload +=
    "\"local_alert\":\"" +
    getLocalAlert() +
    "\",";


  payload +=
    "\"rtc_status\":\"" +
    rtcStatus +
    "\",";


  payload +=
    "\"sd_backup_status\":\"" +
    sdBackupStatus +
    "\",";


  payload +=
    "\"dht22_temperature\":" +
    String(
      dhtTemperature,
      2
    );


  payload +=
    "}";


  // ----------------------------------------------------------
  // SEND
  // ----------------------------------------------------------

  Serial.println();

  Serial.println(
    "Sending reading to MediGuard..."
  );


  Serial.println(
    payload
  );


  HTTPClient http;


  http.setTimeout(
    4000
  );


  if (
    !http.begin(
      sensorURL()
    )
  ) {

    communicationFailure =
      true;


    saveOfflineReading(
      timestamp
    );


    return;
  }


  http.addHeader(
    "Content-Type",
    "application/json"
  );


  int httpCode =
    http.POST(
      payload
    );


  String response =
    "";


  if (
    httpCode > 0
  ) {

    response =
      http.getString();
  }


  Serial.print(
    "HTTP CODE: "
  );


  Serial.println(
    httpCode
  );


  if (
    response.length() >
    0
  ) {

    Serial.println(
      response
    );
  }


  // ==========================================================
  // HTTP 200
  // ==========================================================

  if (
    httpCode ==
    200
  ) {

    communicationFailure =
      false;


    apiRejected =
      false;


    if (sdOK) {

      sdBackupStatus =
        "NOT_REQUIRED";
    }

    else {

      sdBackupStatus =
        "SD_MISSING";
    }
  }


  // ==========================================================
  // SECURITY REJECTION
  // ==========================================================

  else if (
    httpCode ==
    401
  ) {

    communicationFailure =
      false;


    apiRejected =
      false;


    cyberAlert =
      true;


    Serial.println(
      "CYBERSECURITY ALERT: request rejected"
    );
  }


  // ==========================================================
  // OTHER CLIENT/API ERROR
  // ==========================================================

  else if (
    httpCode >= 400 &&
    httpCode < 500
  ) {

    communicationFailure =
      false;


    apiRejected =
      true;


    Serial.println(
      "API REQUEST REJECTED"
    );
  }


  // ==========================================================
  // NETWORK / SERVER FAILURE
  // ==========================================================

  else {

    communicationFailure =
      true;


    Serial.println(
      "Communication failure"
    );


    saveOfflineReading(
      timestamp
    );
  }


  http.end();


  // ----------------------------------------------------------
  // Ask backend for cyber state
  // ----------------------------------------------------------

  if (
    !communicationFailure
  ) {

    fetchCyberStatus();
  }
}


// ============================================================
// HARDWARE FAILURE STATE
// ============================================================

bool hardwareFailure() {

  if (sensorFailure) {

    return true;
  }


  if (!oledOK) {

    return true;
  }


  if (!rtcOK) {

    return true;
  }


  return false;
}


// ============================================================
// LED CONTROL
// ============================================================

void updateLEDs() {

  // ----------------------------------------------------------
  // Clear environmental LEDs
  // ----------------------------------------------------------

  digitalWrite(
    GREEN_LED,
    LOW
  );

  digitalWrite(
    YELLOW_LED,
    LOW
  );

  digitalWrite(
    RED_LED,
    LOW
  );


  // ----------------------------------------------------------
  // ORANGE
  // Hardware or API problem
  // ----------------------------------------------------------

  if (
    hardwareFailure() ||
    apiRejected
  ) {

    digitalWrite(
      ORANGE_LED,
      HIGH
    );
  }

  else {

    digitalWrite(
      ORANGE_LED,
      LOW
    );
  }


  // ----------------------------------------------------------
  // BLUE
  // Communication offline
  // ----------------------------------------------------------

  if (
    communicationFailure
  ) {

    digitalWrite(
      BLUE_LED,
      HIGH
    );
  }

  else {

    digitalWrite(
      BLUE_LED,
      LOW
    );
  }


  // ----------------------------------------------------------
  // If sensors failed:
  // no environmental color
  // ----------------------------------------------------------

  if (sensorFailure) {

    return;
  }


  // ----------------------------------------------------------
  // CYBER ALERT
  // Red blinking
  // ----------------------------------------------------------

  if (cyberAlert) {

    bool blinkState =
      (
        (
          millis() /
          300
        )
        %
        2
      );


    digitalWrite(
      RED_LED,
      blinkState ?
      HIGH :
      LOW
    );


    return;
  }


  // ----------------------------------------------------------
  // NORMAL
  // ----------------------------------------------------------

  if (
    environmentStatus ==
    "NORMAL"
  ) {

    digitalWrite(
      GREEN_LED,
      HIGH
    );
  }


  // ----------------------------------------------------------
  // WARNING
  // ----------------------------------------------------------

  else if (
    environmentStatus ==
    "WARNING"
  ) {

    digitalWrite(
      YELLOW_LED,
      HIGH
    );
  }


  // ----------------------------------------------------------
  // CRITICAL
  // ----------------------------------------------------------

  else if (
    environmentStatus ==
    "CRITICAL"
  ) {

    digitalWrite(
      RED_LED,
      HIGH
    );
  }
}


// ============================================================
// OLED SYSTEM STATUS
// ============================================================

String getSystemStatus() {

  if (
    sensorFailure
  ) {

    return
      "SENSOR FAIL";
  }


  if (
    cyberAlert
  ) {

    return
      "CYBER ALERT";
  }


  if (
    communicationFailure
  ) {

    return
      "OFFLINE";
  }


  if (
    apiRejected
  ) {

    return
      "API REJECT";
  }


  if (
    hardwareFailure()
  ) {

    return
      "HW WARNING";
  }


  return
    "SECURE";
}


// ============================================================
// OLED DISPLAY
// ============================================================

void updateOLED() {

  if (!oledOK) {

    return;
  }


  display.clearDisplay();


  display.setTextColor(
    SSD1306_WHITE
  );


  display.setTextSize(
    1
  );


  // ----------------------------------------------------------
  // LINE 1
  // ----------------------------------------------------------

  display.setCursor(
    0,
    0
  );


  display.print(
    "MediGuard AI"
  );


  // ----------------------------------------------------------
  // LINE 2
  // Temperature + humidity
  // ----------------------------------------------------------

  display.setCursor(
    0,
    8
  );


  if (
    sensorFailure
  ) {

    display.print(
      "T:ERR H:ERR"
    );
  }

  else {

    display.print(
      "T:"
    );


    display.print(
      temperature,
      1
    );


    display.print(
      "C H:"
    );


    display.print(
      humidity,
      0
    );


    display.print(
      "%"
    );
  }


  // ----------------------------------------------------------
  // LINE 3
  // Environmental state
  // ----------------------------------------------------------

  display.setCursor(
    0,
    16
  );


  display.print(
    "ENV:"
  );


  display.print(
    environmentStatus
  );


  // ----------------------------------------------------------
  // LINE 4
  // System/security state
  // ----------------------------------------------------------

  display.setCursor(
    0,
    24
  );


  display.print(
    "SYS:"
  );


  display.print(
    getSystemStatus()
  );


  display.display();
}


// ============================================================
// BUZZER
// ============================================================

void beepOnce() {

#if ENABLE_BUZZER

  digitalWrite(
    BUZZER_PIN,
    HIGH
  );


  delay(300);


  digitalWrite(
    BUZZER_PIN,
    LOW
  );

#endif
}


// ============================================================
// BUZZER LOGIC
// ============================================================

void handleBuzzer() {

  bool issue =

    sensorFailure ||

    environmentStatus ==
      "WARNING" ||

    environmentStatus ==
      "CRITICAL" ||

    cyberAlert;


  if (
    issue &&
    !issueAlreadyBeeped
  ) {

    beepOnce();


    issueAlreadyBeeped =
      true;
  }


  if (!issue) {

    issueAlreadyBeeped =
      false;
  }
}


// ============================================================
// SETUP
// ============================================================

void setup() {

  Serial.begin(
    115200
  );


  delay(1000);


  Serial.println();

  Serial.println(
    "================================"
  );

  Serial.println(
    "       MEDIGUARD AI"
  );

  Serial.println(
    " Enhanced Hardware Starting..."
  );

  Serial.println(
    "================================"
  );


  // ==========================================================
  // LED PINS
  // ==========================================================

  pinMode(
    GREEN_LED,
    OUTPUT
  );

  pinMode(
    YELLOW_LED,
    OUTPUT
  );

  pinMode(
    ORANGE_LED,
    OUTPUT
  );

  pinMode(
    RED_LED,
    OUTPUT
  );

  pinMode(
    BLUE_LED,
    OUTPUT
  );


  digitalWrite(
    GREEN_LED,
    LOW
  );

  digitalWrite(
    YELLOW_LED,
    LOW
  );

  digitalWrite(
    ORANGE_LED,
    LOW
  );

  digitalWrite(
    RED_LED,
    LOW
  );

  digitalWrite(
    BLUE_LED,
    LOW
  );


#if ENABLE_BUZZER

  pinMode(
    BUZZER_PIN,
    OUTPUT
  );


  digitalWrite(
    BUZZER_PIN,
    LOW
  );

#endif


  // ==========================================================
  // I2C
  // ==========================================================

  Wire.begin(
    SDA_PIN,
    SCL_PIN
  );


  // ==========================================================
  // SENSORS
  // ==========================================================

  dht.begin();


  ds18b20.begin();


  // ==========================================================
  // RTC
  // ==========================================================

  rtcOK =
    rtc.begin();


  if (rtcOK) {

    Serial.println(
      "RTC: OK"
    );


    DateTime test =
      rtc.now();


    Serial.print(
      "RTC Date: "
    );


    Serial.print(
      test.year()
    );

    Serial.print("/");

    Serial.print(
      test.month()
    );

    Serial.print("/");

    Serial.println(
      test.day()
    );


    Serial.print(
      "RTC Time: "
    );


    Serial.print(
      test.hour()
    );

    Serial.print(":");

    Serial.print(
      test.minute()
    );

    Serial.print(":");

    Serial.println(
      test.second()
    );
  }

  else {

    Serial.println(
      "RTC: FAILED"
    );
  }


  // ==========================================================
  // OLED
  // ==========================================================

  oledOK =
    display.begin(
      SSD1306_SWITCHCAPVCC,
      OLED_ADDRESS
    );


  if (oledOK) {

    Serial.println(
      "OLED: OK"
    );


    display.clearDisplay();


    display.setTextColor(
      SSD1306_WHITE
    );


    display.setTextSize(
      1
    );


    display.setCursor(
      0,
      0
    );


    display.println(
      "MediGuard AI"
    );


    display.println(
      "Starting..."
    );


    display.display();
  }

  else {

    Serial.println(
      "OLED: FAILED"
    );
  }


  // ==========================================================
  // MICROSD
  // ==========================================================

  initializeSD();


  // ==========================================================
  // WIFI
  // ==========================================================

  connectWiFi();


  // ==========================================================
  // NTP IF WIFI AVAILABLE
  // ==========================================================

  if (
    WiFi.status() ==
    WL_CONNECTED
  ) {

    syncNTP();
  }


  // ==========================================================
  // INITIAL SENSOR READ
  // ==========================================================

  readSensors();


  // ==========================================================
  // SHOW CURRENT TIME SOURCE
  // ==========================================================

  uint32_t testTimestamp =
    getTimestamp();


  Serial.print(
    "Initial timestamp: "
  );


  Serial.println(
    testTimestamp
  );


  Serial.print(
    "Time source: "
  );


  Serial.println(
    rtcStatus
  );


  // ==========================================================
  // INITIAL DISPLAY / LEDs
  // ==========================================================

  updateLEDs();


  updateOLED();
}


// ============================================================
// MAIN LOOP
// ============================================================

void loop() {

  unsigned long currentMillis =
    millis();


  // ==========================================================
  // MAINTAIN WIFI
  // ==========================================================

  maintainWiFi();


  // ==========================================================
  // RETRY NTP
  // ==========================================================

  if (

    WiFi.status() ==
      WL_CONNECTED

    &&

    !ntpSynced

    &&

    currentMillis -
      lastNtpRetry >=
      NTP_RETRY

  ) {

    lastNtpRetry =
      currentMillis;


    syncNTP();
  }


  // ==========================================================
  // READ SENSORS
  // ==========================================================

  if (

    currentMillis -
      lastSensorRead >=
      SENSOR_INTERVAL

  ) {

    lastSensorRead =
      currentMillis;


    readSensors();
  }


  // ==========================================================
  // SEND TO SERVER
  // ==========================================================

  if (

    currentMillis -
      lastServerSend >=
      SERVER_INTERVAL

  ) {

    lastServerSend =
      currentMillis;


    sendToFlask();
  }


  // ==========================================================
  // OLED + LEDs
  // ==========================================================

  if (

    currentMillis -
      lastDisplayUpdate >=
      DISPLAY_INTERVAL

  ) {

    lastDisplayUpdate =
      currentMillis;


    updateLEDs();


    updateOLED();


    handleBuzzer();
  }


  delay(10);
}