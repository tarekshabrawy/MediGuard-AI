#include <WiFi.h>
#include <HTTPClient.h>
#include <Wire.h>
#include <SPI.h>
#include <SD.h>
#include <OneWire.h>
#include <DallasTemperature.h>
#include <DHT.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <RTClib.h>
#include <mbedtls/md.h>
#include <esp_system.h>
#include <time.h>

// Configure these values before uploading.
const char* WIFI_SSID = "PUT_WIFI_NAME_HERE";
const char* WIFI_PASSWORD = "PUT_WIFI_PASSWORD_HERE";
const char* SERVER_URL = "http://192.168.100.23:5000/api/sensor_reading";
const char* SHARED_SECRET = "MEDIGUARD_SENSOR_SECRET_123";
const char* SENSOR_ID = "ESP32_ROOM_1";

const int DEVICE_INDEX = 0;
const int DS18B20_PIN = 27;
const int DHT22_PIN = 26;
const int GREEN_LED_PIN = 16;
const int YELLOW_LED_PIN = 17;
const int ORANGE_LED_PIN = 14;
const int RED_LED_PIN = 25;
const int BLUE_LED_PIN = 32;
const int BUZZER_PIN = 33;
const int OLED_SDA_PIN = 21;
const int OLED_SCL_PIN = 22;
const int SD_MISO_PIN = 19;
const int SD_MOSI_PIN = 23;
const int SD_SCK_PIN = 18;
const int SD_CS_PIN = 13;

const unsigned long READING_INTERVAL_MS = 5000;
const unsigned long WIFI_RETRY_INTERVAL_MS = 10000;
const unsigned long NTP_WAIT_MS = 3000;
const int SCREEN_WIDTH = 128;
const int SCREEN_HEIGHT = 32;

OneWire oneWire(DS18B20_PIN);
DallasTemperature ds18b20(&oneWire);
DHT dht22(DHT22_PIN, DHT22);
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, -1);
RTC_DS3231 rtc;

bool rtcAvailable = false;
bool sdAvailable = false;
bool ntpTimeValid = false;
bool displayAvailable = false;
unsigned long lastReadingMs = 0;
unsigned long lastWiFiAttemptMs = 0;
String lastHttpStatus = "-";
String lastTimeSource = "TIME:INVALID";

enum MainStatus {
  STATUS_NORMAL,
  STATUS_ENV_WARNING,
  STATUS_ENV_CRITICAL,
  STATUS_HARDWARE,
  STATUS_OFFLINE,
  STATUS_CYBER
};

struct ServerSecurityStatus {
  bool reachable;
  bool activeCyberAlert;
  String securityStatus;
  String attackType;
  String attackReason;
  int riskScore;
  String riskLevel;
  String environmentStatus;
  String recommendedAction;
  String lastSecurityEventTime;
};

MainStatus lastMainStatus = STATUS_NORMAL;
bool hasPreviousMainStatus = false;
bool lastCyberAlert = false;
bool lastHardwareIssue = false;
bool lastCommunicationIssue = false;

String twoDecimals(float value) {
  return String(value, 2);
}

bool isValidMeasurement(float value) {
  return !isnan(value) && !isinf(value);
}

void connectWiFi() {
  if (WiFi.status() == WL_CONNECTED) {
    return;
  }

  if (lastWiFiAttemptMs != 0 && millis() - lastWiFiAttemptMs < WIFI_RETRY_INTERVAL_MS) {
    return;
  }

  lastWiFiAttemptMs = millis();
  Serial.printf("Wi-Fi connecting to %s\n", WIFI_SSID);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  unsigned long started = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - started < 10000) {
    delay(250);
    Serial.print(".");
  }
  Serial.println();

  if (WiFi.status() == WL_CONNECTED) {
    Serial.print("Wi-Fi connected. IP: ");
    Serial.println(WiFi.localIP());
  } else {
    Serial.println("Wi-Fi connection failed");
  }
}

bool syncTimeWithNTP() {
  if (WiFi.status() != WL_CONNECTED) {
    return false;
  }

  configTime(0, 0, "pool.ntp.org", "time.nist.gov");
  struct tm timeInfo;
  if (!getLocalTime(&timeInfo, NTP_WAIT_MS)) {
    Serial.println("NTP time unavailable");
    return false;
  }

  time_t now = mktime(&timeInfo);
  if (now < 1700000000) {
    Serial.println("NTP returned an invalid timestamp");
    return false;
  }

  ntpTimeValid = true;
  lastTimeSource = "TIME:NTP";
  if (rtcAvailable) {
    rtc.adjust(DateTime((uint32_t)now));
    Serial.println("RTC updated from NTP");
  }
  Serial.printf("NTP timestamp: %ld\n", (long)now);
  return true;
}

bool getUnixTimestamp(uint32_t& timestamp, String& source) {
  time_t systemNow = time(nullptr);
  if (ntpTimeValid && systemNow >= 1700000000) {
    timestamp = (uint32_t)systemNow;
    source = "NTP_SYNCED";
    lastTimeSource = "TIME:NTP";
    return true;
  }

  if (rtcAvailable) {
    DateTime rtcNow = rtc.now();
    if (rtcNow.year() >= 2023 && rtcNow.unixtime() >= 1700000000) {
      timestamp = rtcNow.unixtime();
      source = "RTC_VALID";
      lastTimeSource = "TIME:RTC";
      return true;
    }
  }

  source = "RTC_INVALID";
  lastTimeSource = "TIME:INVALID";
  return false;
}

String hmacSHA256(const String& message) {
  byte digest[32];
  const mbedtls_md_info_t* mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  mbedtls_md_context_t context;
  mbedtls_md_init(&context);
  mbedtls_md_setup(&context, mdInfo, 1);
  mbedtls_md_hmac_starts(&context, (const unsigned char*)SHARED_SECRET, strlen(SHARED_SECRET));
  mbedtls_md_hmac_update(&context, (const unsigned char*)message.c_str(), message.length());
  mbedtls_md_hmac_finish(&context, digest);
  mbedtls_md_free(&context);

  String result;
  result.reserve(64);
  for (byte value : digest) {
    if (value < 16) {
      result += "0";
    }
    result += String(value, HEX);
  }
  result.toLowerCase();
  return result;
}

String makeNonce(uint32_t timestamp) {
  char nonce[32];
  snprintf(nonce, sizeof(nonce), "%08lx%08lx", (unsigned long)esp_random(), (unsigned long)(millis() ^ timestamp));
  return String(nonce);
}

String jsonStringValue(const String& body, const String& key, const String& fallback = "-") {
  String marker = "\"" + key + "\":";
  int start = body.indexOf(marker);
  if (start < 0) return fallback;
  start += marker.length();
  while (start < (int)body.length() && (body[start] == ' ' || body[start] == '\t')) start++;
  if (start >= (int)body.length()) return fallback;
  if (body[start] == '"') {
    start++;
    int end = body.indexOf('"', start);
    return end < 0 ? fallback : body.substring(start, end);
  }
  int end = body.indexOf(',', start);
  if (end < 0) end = body.indexOf('}', start);
  return end < 0 ? fallback : body.substring(start, end);
}

bool jsonBoolValue(const String& body, const String& key) {
  return jsonStringValue(body, key, "false").equalsIgnoreCase("true");
}

void updateLEDsForStatus(MainStatus status, bool hardwareIssue, bool communicationIssue, bool environmentWarning, bool environmentCritical, bool cyberAlert) {
  bool blinkOn = ((millis() / 350) % 2) == 0;
  digitalWrite(GREEN_LED_PIN, status == STATUS_NORMAL ? HIGH : LOW);
  digitalWrite(YELLOW_LED_PIN, environmentWarning && (status != STATUS_CYBER || blinkOn) ? HIGH : LOW);
  digitalWrite(RED_LED_PIN, cyberAlert ? (blinkOn ? HIGH : LOW) : (environmentCritical ? HIGH : LOW));
  digitalWrite(ORANGE_LED_PIN, hardwareIssue && (status != STATUS_CYBER || blinkOn) ? HIGH : LOW);
  digitalWrite(BLUE_LED_PIN, communicationIssue || cyberAlert ? (blinkOn ? HIGH : LOW) : LOW);
}

void playBuzzerPattern(MainStatus status, bool cyberAlert, bool environmentCritical, bool hardwareIssue, bool communicationIssue) {
  bool newIssue = !hasPreviousMainStatus || status != lastMainStatus || cyberAlert != lastCyberAlert ||
                  lastHardwareIssue != hardwareIssue || lastCommunicationIssue != communicationIssue;
  if (!newIssue) return;

  int beeps = 0;
  int onTime = 0;
  int offTime = 0;
  if (cyberAlert) {
    beeps = 5; onTime = 70; offTime = 70;
  } else if (environmentCritical) {
    beeps = 3; onTime = 100; offTime = 100;
  } else if (status == STATUS_HARDWARE) {
    beeps = 2; onTime = 220; offTime = 160;
  } else if (status == STATUS_OFFLINE) {
    beeps = 2; onTime = 350; offTime = 250;
  } else if (status == STATUS_ENV_WARNING) {
    beeps = 1; onTime = 100; offTime = 0;
  }

  for (int i = 0; i < beeps; i++) {
    tone(BUZZER_PIN, cyberAlert ? 1800 : 1000);
    delay(onTime);
    noTone(BUZZER_PIN);
    if (i + 1 < beeps) delay(offTime);
  }
  if (beeps > 0) Serial.println("Buzzer: one-time status pattern");
}

void updateOLEDStatus(const String& temperature, const String& humidity, const String& status, const String& action) {
  if (!displayAvailable) {
    return;
  }

  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  display.println("MediGuard AI");
  display.setCursor(0, 8);
  display.printf("T:%sC H:%s%%", temperature.c_str(), humidity.c_str());
  display.setCursor(0, 16);
  display.println(status.substring(0, 21));
  display.setCursor(0, 24);
  display.println(action.substring(0, 21));
  display.display();
}

MainStatus determineLocalStatus(bool hardwareIssue, bool communicationIssue, bool environmentCritical, bool environmentWarning) {
  if (communicationIssue) return STATUS_OFFLINE;
  if (hardwareIssue) return STATUS_HARDWARE;
  if (environmentCritical) return STATUS_ENV_CRITICAL;
  if (environmentWarning) return STATUS_ENV_WARNING;
  return STATUS_NORMAL;
}

MainStatus determineMainStatus(MainStatus localStatus, bool activeCyberAlert) {
  return activeCyberAlert ? STATUS_CYBER : localStatus;
}

String mainStatusText(MainStatus status, bool environmentCritical, bool hardwareIssue) {
  if (status == STATUS_CYBER && environmentCritical) return "CYBER + ENV";
  if (status == STATUS_CYBER && hardwareIssue) return "CYBER + HW";
  if (status == STATUS_CYBER) return "CYBER ALERT";
  if (status == STATUS_OFFLINE) return "OFFLINE BACKUP";
  if (status == STATUS_HARDWARE) return "HW WARNING";
  if (status == STATUS_ENV_CRITICAL) return "ENV CRITICAL";
  if (status == STATUS_ENV_WARNING) return "ENV WARNING";
  return "NORMAL SECURE";
}

String escapeJson(const String& value) {
  String escaped = value;
  escaped.replace("\\", "\\\\");
  escaped.replace("\"", "\\\"");
  return escaped;
}

String buildPayload(const String& temperature, const String& humidity, uint32_t timestamp, const String& nonce, const String& signature, const String& localAlert, const String& rtcStatus, const String& sdStatus, const String& dhtTemperature) {
  String payload = "{";
  payload += "\"device_index\":0,";
  payload += "\"sensor_id\":\"" + String(SENSOR_ID) + "\",";
  payload += "\"temperature\":\"" + temperature + "\",";
  payload += "\"humidity\":\"" + humidity + "\",";
  payload += "\"timestamp\":" + String(timestamp) + ",";
  payload += "\"nonce\":\"" + nonce + "\",";
  payload += "\"signature\":\"" + signature + "\",";
  payload += "\"hardware_profile\":\"ESP32_DS18B20_DHT22_OLED_RTC_SD\",";
  payload += "\"local_alert\":\"" + escapeJson(localAlert) + "\",";
  payload += "\"rtc_status\":\"" + rtcStatus + "\",";
  payload += "\"sd_backup_status\":\"" + sdStatus + "\",";
  payload += "\"dht22_temperature\":\"" + dhtTemperature + "\"";
  payload += "}";
  return payload;
}

bool backupToSD(const String& payload, String& status) {
  if (!sdAvailable) {
    status = "SD_MISSING";
    return false;
  }

  File backupFile = SD.open("/offline_backup.jsonl", FILE_APPEND);
  if (!backupFile) {
    status = "BACKUP_FAILED";
    Serial.println("SD backup failed: file could not be opened");
    return false;
  }
  backupFile.println(payload);
  backupFile.close();
  status = "BACKUP_SAVED";
  Serial.println("Offline JSON backup saved to SD");
  return true;
}

void sendReadingToFlask(const String& payload) {
  if (WiFi.status() != WL_CONNECTED) {
    lastHttpStatus = "HTTP:OFFLINE";
    Serial.println("HTTP skipped: Wi-Fi offline");
    return;
  }

  HTTPClient http;
  http.begin(SERVER_URL);
  http.addHeader("Content-Type", "application/json");
  int responseCode = http.POST(payload);
  lastHttpStatus = responseCode > 0 ? "HTTP:" + String(responseCode) : "HTTP:FAIL";
  Serial.printf("HTTP response code: %d\n", responseCode);
  if (responseCode > 0) {
    Serial.println("Flask response body:");
    Serial.println(http.getString());
  } else {
    Serial.println("Flask response unavailable");
  }
  http.end();
}

bool fetchServerSecurityStatus(ServerSecurityStatus& status) {
  status.reachable = false;
  status.activeCyberAlert = false;
  status.securityStatus = "Secure";
  status.attackType = "-";
  status.attackReason = "-";
  status.riskScore = 0;
  status.riskLevel = "-";
  status.environmentStatus = "Normal";
  status.recommendedAction = "Check Flask";
  status.lastSecurityEventTime = "";

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("Server/SOC status: skipped; Wi-Fi offline");
    return false;
  }

  String statusUrl = String(SERVER_URL);
  int pathStart = statusUrl.indexOf("/api/");
  if (pathStart >= 0) statusUrl = statusUrl.substring(0, pathStart);
  statusUrl += "/api/hardware_status";

  HTTPClient http;
  http.begin(statusUrl);
  int responseCode = http.GET();
  String body = responseCode > 0 ? http.getString() : "";
  http.end();
  Serial.printf("Server/SOC status HTTP response: %d\n", responseCode);
  Serial.println("Server/SOC status body:");
  Serial.println(body);

  if (responseCode != 200) return false;
  status.reachable = true;
  status.activeCyberAlert = jsonBoolValue(body, "active_cyber_alert");
  status.securityStatus = jsonStringValue(body, "security_status");
  status.attackType = jsonStringValue(body, "attack_type");
  status.attackReason = jsonStringValue(body, "attack_reason");
  status.riskScore = jsonStringValue(body, "risk_score", "0").toInt();
  status.riskLevel = jsonStringValue(body, "risk_level");
  status.environmentStatus = jsonStringValue(body, "environment_status", "Normal");
  status.recommendedAction = jsonStringValue(body, "recommended_action", "Check SOC");
  status.lastSecurityEventTime = jsonStringValue(body, "last_security_event_time", "");
  Serial.printf("Server/SOC status: %s, cyber=%s, attack=%s, reason=%s, risk=%d/%s\n",
                status.securityStatus.c_str(), status.activeCyberAlert ? "true" : "false",
                status.attackType.c_str(), status.attackReason.c_str(), status.riskScore, status.riskLevel.c_str());
  return true;
}

void setup() {
  Serial.begin(115200);
  delay(200);

  pinMode(GREEN_LED_PIN, OUTPUT);
  pinMode(YELLOW_LED_PIN, OUTPUT);
  pinMode(ORANGE_LED_PIN, OUTPUT);
  pinMode(RED_LED_PIN, OUTPUT);
  pinMode(BLUE_LED_PIN, OUTPUT);
  pinMode(BUZZER_PIN, OUTPUT);
  digitalWrite(BUZZER_PIN, LOW);
  updateLEDsForStatus(STATUS_HARDWARE, true, true, false, false, false);

  Wire.begin(OLED_SDA_PIN, OLED_SCL_PIN);
  displayAvailable = display.begin(SSD1306_SWITCHCAPVCC, 0x3C);
  if (!displayAvailable) {
    Serial.println("OLED unavailable");
  }
  updateOLEDStatus("--", "--", "HW WARNING", "OLED STARTUP");

  rtcAvailable = rtc.begin();
  if (rtcAvailable) {
    Serial.println(rtc.lostPower() ? "RTC available but time may be invalid" : "DS3231 RTC available");
  } else {
    Serial.println("DS3231 RTC unavailable");
  }

  ds18b20.begin();
  dht22.begin();

  SPI.begin(SD_SCK_PIN, SD_MISO_PIN, SD_MOSI_PIN, SD_CS_PIN);
  sdAvailable = SD.begin(SD_CS_PIN, SPI);
  Serial.println(sdAvailable ? "MicroSD ready" : "MicroSD unavailable; continuing without SD backup");

  connectWiFi();
  if (WiFi.status() == WL_CONNECTED) {
    syncTimeWithNTP();
  }
}

void loop() {
  connectWiFi();
  if (WiFi.status() == WL_CONNECTED && !ntpTimeValid) {
    syncTimeWithNTP();
  }

  if (millis() - lastReadingMs < READING_INTERVAL_MS) {
    delay(25);
    return;
  }
  lastReadingMs = millis();

  ds18b20.requestTemperatures();
  float temperature = ds18b20.getTempCByIndex(0);
  float humidity = dht22.readHumidity();
  float dhtTemperature = dht22.readTemperature();
  bool ds18b20Error = !isValidMeasurement(temperature) || temperature == DEVICE_DISCONNECTED_C;
  bool dht22HumidityError = !isValidMeasurement(humidity);
  bool dht22TemperatureError = !isValidMeasurement(dhtTemperature);
  bool sensorIssue = ds18b20Error || dht22HumidityError || dht22TemperatureError;

  String temperatureString = isValidMeasurement(temperature) && temperature != DEVICE_DISCONNECTED_C ? twoDecimals(temperature) : "";
  String humidityString = isValidMeasurement(humidity) ? twoDecimals(humidity) : "";
  String dhtTemperatureString = isValidMeasurement(dhtTemperature) ? twoDecimals(dhtTemperature) : "";
  bool critical = !sensorIssue && temperature >= 13.0;
  bool warning = !sensorIssue && !critical && (temperature < 2.0 || (temperature > 8.0 && temperature < 13.0));
  bool timeIssue = false;
  bool communicationIssue = WiFi.status() != WL_CONNECTED;
  String rtcStatus;
  uint32_t timestamp = 0;

  String localAlert = sensorIssue ? "SENSOR_ISSUE" : (critical ? "CRITICAL" : (warning ? "WARNING" : "NORMAL"));
  String sdStatus = sdAvailable ? "SD_READY" : "SD_MISSING";

  if (!sdAvailable && !sensorIssue) {
    localAlert = "SD_MISSING";
  }

  if (!getUnixTimestamp(timestamp, rtcStatus)) {
    timeIssue = true;
    localAlert = "RTC_TIME_ISSUE";
  }

  bool hardwareIssue = sensorIssue || timeIssue;
  bool sdBackupFailure = false;

  Serial.printf("DS18B20 error: %s\n", ds18b20Error ? "true" : "false");
  Serial.printf("DHT22 error: %s (humidity=%s, temperature=%s)\n",
                (dht22HumidityError || dht22TemperatureError) ? "true" : "false",
                dht22HumidityError ? "true" : "false", dht22TemperatureError ? "true" : "false");
  Serial.printf("RTC invalid: %s\n", timeIssue ? "true" : "false");
  Serial.printf("SD missing: %s\n", !sdAvailable ? "true" : "false");
  Serial.println("SD backup failed: false");
  Serial.printf("Local hardware issue: %s\n", hardwareIssue ? "true" : "false");

  Serial.printf("Sensor readings: DS18B20=%s C, DHT22=%s C, humidity=%s %%\n", temperatureString.c_str(), dhtTemperatureString.c_str(), humidityString.c_str());
  Serial.printf("Timestamp source: %s, timestamp: %lu\n", rtcStatus.c_str(), (unsigned long)timestamp);
  Serial.printf("Local alert: %s, RTC: %s, SD: %s\n", localAlert.c_str(), rtcStatus.c_str(), sdStatus.c_str());

  if (sensorIssue || timeIssue) {
    lastHttpStatus = timeIssue ? "TIME:INVALID" : "SENSOR:FAIL";
    communicationIssue = WiFi.status() != WL_CONNECTED;
    ServerSecurityStatus serverStatus;
    bool serverReachable = fetchServerSecurityStatus(serverStatus);
    communicationIssue = communicationIssue || !serverReachable;
    MainStatus localStatus = determineLocalStatus(hardwareIssue, communicationIssue, critical, warning);
    MainStatus mainStatus = determineMainStatus(localStatus, serverStatus.activeCyberAlert);
    updateLEDsForStatus(mainStatus, hardwareIssue, communicationIssue, warning, critical, serverStatus.activeCyberAlert);
    playBuzzerPattern(mainStatus, serverStatus.activeCyberAlert, critical, hardwareIssue, communicationIssue);
    updateOLEDStatus(temperatureString.length() ? temperatureString : "--", humidityString.length() ? humidityString : "--",
                     mainStatusText(mainStatus, critical, hardwareIssue), serverStatus.activeCyberAlert ? "Check SOC" : lastHttpStatus);
    Serial.printf("Selected main status: %s\n", mainStatusText(mainStatus, critical, hardwareIssue).c_str());
    lastMainStatus = mainStatus;
    hasPreviousMainStatus = true;
    lastCyberAlert = serverStatus.activeCyberAlert;
    lastHardwareIssue = hardwareIssue;
    lastCommunicationIssue = communicationIssue;
    return;
  }

  String nonce = makeNonce(timestamp);
  String hmacMessage = String(SENSOR_ID) + "|" + temperatureString + "|" + humidityString + "|" + String(timestamp) + "|" + nonce;
  String signature = hmacSHA256(hmacMessage);
  String payload = buildPayload(temperatureString, humidityString, timestamp, nonce, signature, localAlert, rtcStatus, sdStatus, dhtTemperatureString);

  Serial.println("HMAC message:");
  Serial.println(hmacMessage);
  Serial.println("JSON payload:");
  Serial.println(payload);

  sendReadingToFlask(payload);
  bool postFailed = lastHttpStatus == "HTTP:OFFLINE" || lastHttpStatus == "HTTP:FAIL" ||
                    (lastHttpStatus.startsWith("HTTP:") && lastHttpStatus != "HTTP:200");
  if (postFailed) {
    bool backupSaved = backupToSD(payload, sdStatus);
    sdBackupFailure = sdAvailable && !backupSaved;
    hardwareIssue = hardwareIssue || sdBackupFailure;
  }

  Serial.printf("SD backup failed: %s\n", sdBackupFailure ? "true" : "false");
  Serial.printf("Local hardware issue: %s\n", hardwareIssue ? "true" : "false");

  ServerSecurityStatus serverStatus;
  bool serverReachable = fetchServerSecurityStatus(serverStatus);
  communicationIssue = postFailed || !serverReachable || WiFi.status() != WL_CONNECTED;
  MainStatus localStatus = determineLocalStatus(hardwareIssue, communicationIssue, critical, warning);
  MainStatus mainStatus = determineMainStatus(localStatus, serverStatus.activeCyberAlert);
  updateLEDsForStatus(mainStatus, hardwareIssue, communicationIssue, warning, critical, serverStatus.activeCyberAlert);
  playBuzzerPattern(mainStatus, serverStatus.activeCyberAlert, critical, hardwareIssue, communicationIssue);

  String action = serverStatus.activeCyberAlert ? "Check SOC" :
                  (communicationIssue ? (postFailed && sdAvailable ? "Backup saved" : "Check Flask") :
                   (hardwareIssue ? "Check storage" : (critical ? "Move medicine" :
                    (warning ? "Move medicine" : "HTTP 200"))));
  updateOLEDStatus(temperatureString, humidityString, mainStatusText(mainStatus, critical, hardwareIssue), action);
  Serial.printf("Selected main status: %s\n", mainStatusText(mainStatus, critical, hardwareIssue).c_str());
  lastMainStatus = mainStatus;
  hasPreviousMainStatus = true;
  lastCyberAlert = serverStatus.activeCyberAlert;
  lastHardwareIssue = hardwareIssue;
  lastCommunicationIssue = communicationIssue;
}

