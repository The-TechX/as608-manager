#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <Preferences.h>
#include <ESPmDNS.h>
#include <Adafruit_Fingerprint.h>

// AS608 Manager — standalone maintenance firmware.
// Wiring: AS608 TX -> GPIO16, RX -> GPIO17, Touch -> GPIO4.
// Security: LAN-only prototype. HTTP is unencrypted; do not expose to Internet.
constexpr uint8_t PIN_RX = 16, PIN_TX = 17, PIN_TOUCH = 4;
constexpr uint32_t SENSOR_BAUD = 57600;
const char* AP_SSID = "AS608-Manager-Setup";
const char* AP_PASSWORD = "AS608setup!26";
const char* HOSTNAME = "as608-manager";
// Admin credentials are created during first-time SoftAP provisioning.

HardwareSerial sensorUart(2);
Adafruit_Fingerprint sensor(&sensorUart);
WebServer server(80);
DNSServer dns;
Preferences prefs;
Preferences securityPrefs;
String adminUser, adminPassword;
bool adminConfigured = false;

bool setupMode = false;
bool wifiPending = false;
uint32_t wifiStarted = 0, wifiRestartAt = 0;
String wifiTarget, wifiPassword, wifiState = "idle", wifiDetail, wifiNewIP;

bool sensorOnline = false;
bool indexValid = false;
uint16_t sensorCapacity = 0, templateCount = 0, occupiedCount = 0;
uint8_t securityLevel = 0;
uint8_t bitmap[64] = {0}; // Up to 512 slots.
String lastError;
String lastEvent = "Device startup";

// Async fingerprint workflow; no blocking wait for fingers in HTTP callbacks.
enum JobType : uint8_t { JOB_NONE, JOB_IDENTIFY, JOB_ENROLL };
JobType job = JOB_NONE;
uint8_t jobStage = 0;
uint16_t jobId = 0;
uint32_t jobStarted = 0, stageStarted = 0, lastPoll = 0;
String jobMessage = "Ready";
String jobResult = "idle";
String escapeJson(String s);
void jsonResponse(const String& s, int code=200);
// Wake-triggered live recognition. Results are transient in the UI (5s TTL).
bool liveArmed = true;
bool liveActive = false;
uint32_t liveStarted = 0, liveCaptureMs = 0, liveConvertMs = 0, liveSearchMs = 0;
uint32_t liveSequence = 0, liveLastRelease = 0, liveTotalMs = 0, liveFinishedAt = 0;
uint32_t liveFirstImageMs = 0, liveImageCallMs = 0;
uint16_t liveCaptureAttempts = 0, liveNoFingerRetries = 0;
int32_t liveFingerId = -1, liveConfidence = -1;
String liveStatus = "waiting", liveDetail = "Place a finger to identify";
void liveFinish(const String& status, const String& detail) {
  liveActive = false; liveStatus = status; liveDetail = detail; liveTotalMs = millis()-liveStarted;
  liveSequence++;
  liveFinishedAt = millis();
  const uint32_t measured = liveCaptureMs + liveConvertMs + liveSearchMs;
  Serial.printf("[LIVE] %s | %s | total=%lu ms | capture=%lu convert=%lu search=%lu | firstGetImage=%lu ms | imageCalls=%u | noFinger=%u | getImageTotal=%lu ms | overhead=%lu ms\n",
    status.c_str(), detail.c_str(), (unsigned long)(millis()-liveStarted),
    (unsigned long)liveCaptureMs, (unsigned long)liveConvertMs, (unsigned long)liveSearchMs,
    (unsigned long)liveFirstImageMs, liveCaptureAttempts, liveNoFingerRetries,
    (unsigned long)liveImageCallMs, (unsigned long)(liveTotalMs > measured ? liveTotalMs - measured : 0));
}
// Touch is a wake signal, not a guarantee that an optical image is ready.
// Retry capture for up to 900 ms without blocking the HTTP server.
bool liveCapturing = false;
uint32_t liveCaptureDeadline = 0;
void processLive() {
  const bool touched = digitalRead(PIN_TOUCH) == HIGH;
  if (!touched) {
    if (liveLastRelease == 0) liveLastRelease = millis();
    if (millis() - liveLastRelease >= 120) liveArmed = true;
  } else liveLastRelease = 0;

  // Recognition is local and works in STA or SoftAP mode.
  if (job != JOB_NONE || !sensorOnline) {
    liveCapturing = false;
    if (touched) liveArmed = false;
    return;
  }
  if (!liveCapturing) {
    if (!touched || !liveArmed) return;
    liveArmed = false;
    liveCapturing = true;
    liveActive = true;
    liveStarted = millis();
    liveCaptureDeadline = liveStarted + 900;
    liveCaptureMs = liveConvertMs = liveSearchMs = 0;
    liveFirstImageMs = liveImageCallMs = 0;
    liveCaptureAttempts = liveNoFingerRetries = 0;
    liveFingerId = -1; liveConfidence = -1;
    liveStatus = "scanning";
    liveDetail = "Waiting for finger image";
    Serial.println("[LIVE] Wake GPIO4 HIGH; waiting for image");
  }
  if (!touched) {
    liveCapturing = false;
    liveFinish("no_finger", "Finger removed before capture");
    return;
  }
  const uint32_t callStarted = millis();
  uint8_t r = sensor.getImage();
  const uint32_t callElapsed = millis() - callStarted;
  liveCaptureAttempts++;
  liveImageCallMs += callElapsed;
  if (liveCaptureAttempts == 1) liveFirstImageMs = callElapsed;
  liveCaptureMs = millis() - liveStarted;
  if (r == FINGERPRINT_NOFINGER) {
    liveNoFingerRetries++;
    if ((int32_t)(millis() - liveCaptureDeadline) < 0) return;
    liveCapturing = false;
    liveFinish("no_finger", "No image captured within 900 ms; remove and place your finger again");
    return;
  }
  liveCapturing = false;
  if (r != FINGERPRINT_OK) {
    liveFinish("error", "Capture error: " + String(r));
    return;
  }
  liveDetail = "Processing fingerprint";
  uint32_t start = millis();
  r = sensor.image2Tz(1);
  liveConvertMs = millis() - start;
  if (r != FINGERPRINT_OK) {
    liveFinish("error", "Conversion error: " + String(r));
    return;
  }
  liveDetail = "Searching for match";
  start = millis();
  r = sensor.fingerFastSearch();
  liveSearchMs = millis() - start;
  if (r == FINGERPRINT_OK) {
    liveFingerId = sensor.fingerID;
    liveConfidence = sensor.confidence;
    liveFinish("matched", "Template identified");
  } else if (r == FINGERPRINT_NOTFOUND) {
    liveFinish("not_found", "Fingerprint not registered");
  } else {
    liveFinish("error", "Search error: " + String(r));
  }
}
void handleLive(){
  uint32_t total = liveSequence ? liveTotalMs : 0;
  String payload = String("{\"status\":\"") + liveStatus + "\",\"detail\":\"" + escapeJson(liveDetail)
    + "\",\"sequence\":" + String(liveSequence)
    + ",\"touch\":" + (digitalRead(PIN_TOUCH) ? "true" : "false")
    + ",\"id\":" + String(liveFingerId) + ",\"confidence\":" + String(liveConfidence)
    + ",\"captureMs\":" + String(liveCaptureMs) + ",\"convertMs\":" + String(liveConvertMs)
    + ",\"searchMs\":" + String(liveSearchMs) + ",\"totalMs\":" + String(total)
    + ",\"firstImageMs\":" + String(liveFirstImageMs)
    + ",\"imageCallMs\":" + String(liveImageCallMs)
    + ",\"captureAttempts\":" + String(liveCaptureAttempts)
    + ",\"noFingerRetries\":" + String(liveNoFingerRetries)
    + ",\"ageMs\":" + String(liveSequence ? (uint32_t)(millis()-liveFinishedAt) : 0) + "}";
  jsonResponse(payload);
}

const char HTML[] PROGMEM = R"PAGE(
<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AS608 Manager</title><style>
:root{color-scheme:dark;--bg:#09090b;--panel:#0e0e11;--surface:#151518;--line:#27272a;--fg:#fafafa;--muted:#a1a1aa;--green:#22c55e;--red:#ef4444}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.55 system-ui,-apple-system,Segoe UI,sans-serif}
button,input,select{font:inherit}button{border:1px solid #35353a;background:#18181b;color:#fafafa;border-radius:7px;padding:9px 13px;cursor:pointer}button:hover{background:#27272a}button:disabled{opacity:.4;cursor:not-allowed}
button.primary{background:#fafafa;color:#09090b;border-color:#fafafa}button.danger{border-color:#7f1d1d;color:#fca5a5}button.ghost{background:transparent}input,select{width:100%;background:#09090b;color:#fafafa;border:1px solid #38383e;border-radius:7px;padding:10px}
.shell{display:flex;min-height:100vh}.sidebar{width:238px;flex-shrink:0;border-right:1px solid var(--line);padding:25px 14px;display:flex;flex-direction:column;gap:24px}.brand{display:flex;gap:12px;align-items:center;padding:0 9px}.logo{font-size:30px}.brand strong{font-size:17px}.small,.muted{font-size:12px;color:var(--muted)}.nav{display:grid;gap:4px}.nav button{border:0;text-align:left;background:transparent;color:#b4b4bd;padding:10px 13px}.nav button.active{background:#202024;color:white}.sidebottom{margin-top:auto;border:1px solid var(--line);border-radius:10px;padding:13px}
.main{width:100%;max-width:1450px;margin:auto;padding:34px 34px 70px}.top{display:flex;justify-content:space-between;align-items:center;gap:16px;margin-bottom:27px}.top h1{margin:0;font-size:26px;font-weight:650;letter-spacing:-.7px}.top p{margin:4px 0 0;color:var(--muted)}.cards{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px;margin-bottom:17px}.card{border:1px solid var(--line);border-radius:11px;padding:18px;background:var(--panel)}.metric .val{font-size:28px;font-weight:650;letter-spacing:-1px;margin:7px 0 0}.metric .unit{font-size:12px;color:var(--muted)}.metric .symbol{font-size:18px;color:#b4b4bd}.columns{display:grid;grid-template-columns:minmax(0,1.7fr) minmax(280px,1fr);gap:16px}.sectionhead{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:16px}.sectionhead h2{margin:0;font-size:18px;letter-spacing:-.3px}.sectionhead p{margin:2px 0 0;color:var(--muted);font-size:12px}.pill{border:1px solid #303035;border-radius:99px;padding:4px 10px;font-size:12px;color:#ddd}.green{color:var(--green)}.red{color:#f87171}.dot{display:inline-block;width:8px;height:8px;background:#52525b;border-radius:50%;margin-right:7px}.dot.on{background:var(--green)}.kv{display:flex;justify-content:space-between;gap:15px;padding:10px 0;border-bottom:1px solid #232326}.kv:last-child{border:0}.kv span:first-child{color:#a1a1aa}.slotgrid{display:grid;grid-template-columns:repeat(20,minmax(0,1fr));gap:6px}.slot{aspect-ratio:1;border:1px solid #303036;background:#242429;border-radius:4px;padding:0;font-size:10px}.slot.used{background:#166534;border-color:#22c55e;color:#fff}.slot.selected{outline:2px solid white;outline-offset:2px}.legend{display:flex;gap:17px;margin:15px 0 0;color:var(--muted);font-size:12px}.toolbar{display:flex;gap:9px;align-items:center;flex-wrap:wrap}.toolbar select{width:auto}.detail{padding:12px 0;color:var(--muted)}.panelactions{display:flex;gap:8px;flex-wrap:wrap}.view{display:none}.view.active{display:block}.field{margin:14px 0}.field label{display:block;margin-bottom:5px;color:var(--muted)}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#111114;padding:14px;border:1px solid var(--line);border-radius:8px;max-height:460px;overflow:auto}.notice{border:1px solid #3f3f46;padding:12px;border-radius:8px;color:#d4d4d8;margin:12px 0}.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.table{width:100%;border-collapse:collapse}.table th,.table td{padding:11px;border-bottom:1px solid var(--line);text-align:left}.table th{color:var(--muted);font-weight:500}.log{font-family:ui-monospace,monospace;font-size:12px;color:#a1a1aa}
@media(max-width:1050px){.cards{grid-template-columns:repeat(3,1fr)}.columns{grid-template-columns:1fr}}@media(max-width:700px){.shell{display:block}.sidebar{width:auto;border-right:0;border-bottom:1px solid var(--line);padding:12px;gap:10px}.brand{padding:0}.nav{display:flex;overflow-x:auto}.nav button{white-space:nowrap}.sidebottom{display:none}.main{padding:22px 15px}.top{align-items:flex-start}.top h1{font-size:22px}.cards{grid-template-columns:repeat(2,1fr)}.slotgrid{grid-template-columns:repeat(10,1fr)}}

/* Mobile-first refinements */
@media(max-width:700px){
 body{font-size:15px}.sidebar{position:sticky;top:0;z-index:10;background:#09090bf5;gap:8px;padding:10px 12px}
 .brand strong{font-size:15px}.logo{font-size:23px}.brand .muted{font-size:10px}
 .nav{display:flex;gap:6px;margin:0 -12px;padding:0 12px 8px;scrollbar-width:thin}
 .nav button{min-height:44px;border:1px solid #27272a;border-radius:9px;padding:9px 12px;flex-shrink:0}
 .nav button.active{border-color:#71717a}.main{padding:18px 12px 48px}
 .top{gap:8px;margin-bottom:18px}.top h1{font-size:21px}.top p{font-size:12px}
 .top button{padding:10px;min-height:44px}.cards{grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}
 .card{padding:14px;border-radius:12px;min-width:0}.metric .val{font-size:25px}
 .columns{grid-template-columns:minmax(0,1fr);gap:10px}.sectionhead{flex-wrap:wrap}
 .slotgrid{grid-template-columns:repeat(10,minmax(0,1fr));gap:5px}
 .slot{min-width:0;min-height:24px;font-size:10px}.panelactions{display:grid;grid-template-columns:1fr}
 .panelactions button, .field input, .toolbar button{min-height:46px}
 .kv{overflow-wrap:anywhere;align-items:flex-start}.kv span:last-child{text-align:right;min-width:0}
 #networks button{min-height:44px;text-align:left}.table{display:block;overflow-x:auto}
}
@media(max-width:370px){.slotgrid{gap:3px}.slot{min-height:22px}.metric .val{font-size:22px}}
.live-card{max-width:720px;margin:auto;padding:22px}.live-top{display:flex;justify-content:space-between;align-items:center;gap:12px}.live-hero{text-align:center;padding:45px 8px 25px;position:relative;isolation:isolate}.live-glow{position:absolute;z-index:-1;inset:2% 8% 4%;border-radius:50%;pointer-events:none;opacity:0;transition:opacity .65s ease-in-out;will-change:opacity}
.live-glow.neutral{background:radial-gradient(ellipse at center,rgba(113,113,122,.12),transparent 68%);opacity:1}
.live-glow.success{background:radial-gradient(ellipse at center,rgba(34,197,94,.19),transparent 68%)}
.live-glow.failure{background:radial-gradient(ellipse at center,rgba(244,63,94,.17),transparent 68%)}
.live-hero:has(.finger-orb.matched) .live-glow.neutral,.live-hero:has(.finger-orb.not_found) .live-glow.neutral,.live-hero:has(.finger-orb.error) .live-glow.neutral,.live-hero:has(.finger-orb.no_finger) .live-glow.neutral{opacity:0}
.live-hero:has(.finger-orb.matched) .live-glow.success{opacity:1}
.live-hero:has(.finger-orb.not_found) .live-glow.failure,.live-hero:has(.finger-orb.error) .live-glow.failure,.live-hero:has(.finger-orb.no_finger) .live-glow.failure{opacity:1}
.finger-orb{height:164px;width:164px;border-radius:50%;display:grid;place-items:center;margin:0 auto 23px;background:radial-gradient(circle,#29292d,#1b1b20 68%,#16161a);border:1px solid #45454d;color:#a1a1aa;box-shadow:0 0 26px rgba(161,161,170,.07);transition:background .65s ease,border-color .65s ease,color .65s ease,box-shadow .65s ease,transform .65s ease}.finger-orb.scanning{animation:scanPulse 1.2s infinite alternate}.finger-orb.matched{background:radial-gradient(circle,#1a4531,#10281d 68%,#101814);color:#4ade80;border-color:#4ade80;box-shadow:0 0 45px rgba(34,197,94,.25)}.finger-orb.not_found,.finger-orb.error,.finger-orb.no_finger{background:radial-gradient(circle,#4a1e29,#2a141b 68%,#1b1115);color:#fb7185;border-color:#fb7185;box-shadow:0 0 45px rgba(244,63,94,.23)}.live-hero h2{font-size:25px;margin:0}.live-hero p{color:var(--muted);margin:7px 0}.live-id{font-size:22px;font-weight:700;margin-top:12px}.live-metrics{display:grid;grid-template-columns:1fr 1fr;gap:12px}.live-metrics>div{background:#18181b;border:1px solid #303035;border-radius:12px;padding:16px}.live-metrics span,.live-metrics small{display:block;color:var(--muted);font-size:12px}.live-metrics strong{display:block;font-size:30px;margin:5px 0}.live-timings{display:flex;justify-content:space-around;gap:10px;flex-wrap:wrap;margin:20px 0;color:var(--muted);font-size:12px}.live-breakdown{margin:12px 0 20px;border-top:1px solid var(--line);padding-top:8px}.live-breakdown .kv strong{font-variant-numeric:tabular-nums}.live-card #liveFooter{text-align:center;border-top:1px solid var(--line);padding-top:16px}@keyframes scanPulse{to{box-shadow:0 0 28px rgba(161,161,170,.19);transform:scale(1.025)}}@media(max-width:480px){.live-card{padding:14px}.live-hero{padding:30px 0 20px}.finger-orb{height:145px;width:145px}.live-metrics strong{font-size:24px}}@media(prefers-reduced-motion:reduce){.finger-orb,.live-glow{transition:none}.finger-orb.scanning{animation:none}}
</style></head><body><div class="shell"><aside class="sidebar"><div class="brand"><span class="logo">AS</span><div><strong>AS608 Manager</strong><div class="muted">Local Device Manager</div></div></div><nav class="nav" id="nav"><button class="active" data-view="status">Estado</button><button data-view="prints">Fingerprints</button><button data-view="identify">Identify</button><button data-view="diagnostics">Diagnostics</button><button data-view="wifi">Wi-Fi</button><button data-view="system">System</button><button data-view="connections">Connections</button></nav><div class="sidebottom"><b>Device</b><div class="small" id="sidebarInfo">Connecting...</div></div></aside>
<main class="main"><header class="top"><div><h1 id="heading">Sensor status</h1><p id="subtitle">Real-time AS608 information</p></div><button id="refreshBtn" onclick="refresh()">Refresh</button></header>
<section id="status" class="view active"><div class="cards"><div class="card metric"><div class="muted">Capacity</div><div class="val" id="cap">—</div><div class="unit">templates</div></div><div class="card metric"><div class="muted">Enrolled</div><div class="val" id="count">—</div><div class="unit">fingerprints</div></div><div class="card metric"><div class="muted">Available</div><div class="val" id="free">—</div><div class="unit">slots</div></div><div class="card metric"><div class="muted">Security level</div><div class="val" id="level">—</div><div class="unit">sensor configuration</div></div><div class="card metric"><div class="muted">Touch GPIO4</div><div class="val" id="touch">—</div><div class="unit">touch detection</div></div></div>
<div class="columns"><div class="card"><div class="sectionhead"><div><h2>Memory map</h2><p>Sensor slots · select a cell</p></div><select id="page" onchange="drawSlots()"><option value="0">0–99</option><option value="1">100–199</option><option value="2">200–299</option></select></div><div class="slotgrid" id="slots"></div><div class="legend"><span><i class="dot on"></i>Occupied</span><span><i class="dot"></i>Free</span><span id="mapMessage"></span></div></div><div class="card"><div class="sectionhead"><h2>Sensor information</h2><span class="pill" id="online">—</span></div><div id="facts"></div></div></div>
<div class="columns" style="margin-top:16px"><div class="card"><div class="sectionhead"><div><h2>Selected slot</h2><p>Available template actions</p></div><span class="pill" id="selectedId">ID 0</span></div><div class="detail" id="selectedInfo">Select a slot</div><div class="panelactions"><button onclick="showView('prints')">Gestionar fingerprints</button><button onclick="showView('identify')">Identify dedo</button></div></div><div class="card"><div class="sectionhead"><h2>Diagnostics rápido</h2><button onclick="refresh()">Run</button></div><div id="health"></div></div></div></section>
<section id="prints" class="view"><div class="columns"><div class="card"><div class="sectionhead"><div><h2>Gestión de templates</h2><p>Enroll, inspect, and delete IDs</p></div><span class="pill" id="printTotal">—</span></div><div class="field"><label>Template ID (0 to capacity − 1)</label><input id="printId" type="number" min="0" value="1"></div><div class="panelactions"><button class="primary" onclick="startJob('enroll')">Enroll at ID</button><button class="danger" onclick="deleteOne()">Delete ID</button><button onclick="refresh()">Refresh inventory</button></div><div class="notice">Enrollment: place your finger, lift it, and place it again. These actions modify AS608 memory.</div><div class="detail" id="jobState">No active operation</div><button onclick="cancelJob()">Cancel operation</button></div><div class="card"><div class="sectionhead"><h2>Occupied IDs</h2></div><div id="occupiedList" class="muted">—</div></div></div><div class="card"><div class="sectionhead"><h2>Reset biometric memory</h2></div><p class="muted">Borra todas las templates del sensor. No elimina las credenciales Wi-Fi.</p><button class="danger" onclick="clearAll()">Erase AS608 memory</button></div></section>
<section id="identify" class="view"><div class="card live-card"><div class="live-top"><span class="pill green">LIVE MONITOR</span><span class="muted">GPIO4 · Wake trigger</span></div><div class="live-hero" id="liveHero"><div class="live-glow neutral"></div><div class="live-glow success"></div><div class="live-glow failure"></div><div class="finger-orb" id="fingerOrb"></div><h2 id="liveTitle">Waiting for fingerprint</h2><p id="liveDescription">Place your finger on the AS608 sensor</p><div class="live-id" id="liveId">—</div></div><div class="live-metrics"><div><span>AS608 confidence</span><strong id="liveConfidence">—</strong><small>Native score, not a percentage</small></div><div><span>Wake → result</span><strong id="liveLatency">—</strong><small>Total measured time</small></div></div><div class="live-timings"><span id="liveCapture">Capture —</span><span id="liveConvert">Conversion —</span><span id="liveSearch">Search —</span></div><div class="live-breakdown" id="liveBreakdown" hidden><div class="kv"><span>First getImage()</span><strong id="liveFirstImage">—</strong></div><div class="kv"><span>Capture attempts</span><strong id="liveAttempts">—</strong></div><div class="kv"><span>NOFINGER responses</span><strong id="liveRetries">—</strong></div><div class="kv"><span>Total time in getImage()</span><strong id="liveImageCalls">—</strong></div><div class="kv"><span>Time outside measured calls</span><strong id="liveOverhead">—</strong></div></div><div class="muted" id="liveFooter">Automatic identification on GPIO4 HIGH. Remove your finger to rearm.</div></div></section>
<section id="diagnostics" class="view"><div class="card"><div class="sectionhead"><h2>Diagnostics técnico</h2><div class="panelactions"><button onclick="refresh()">Refresh</button><button onclick="exportJSON()">Export JSON</button></div></div><pre id="json">Waiting...</pre></div></section>
<section id="wifi" class="view"><div class="columns"><div class="card"><h2>Connectivity</h2><div id="wifiFacts"></div><button onclick="scanNetworks()">Scan available networks</button><div id="networks" class="detail"></div></div><div class="card"><h2>Provisioning</h2><p class="muted">Connect the device to Wi-Fi. In AP mode, open 192.168.4.1.</p><div class="field"><label>SSID</label><input id="ssid" maxlength="32" autocomplete="off"></div><div class="field"><label>Wi-Fi password</label><input id="password" type="password" autocomplete="off"></div><div class="panelactions"><button class="primary" id="saveWifiBtn" onclick="saveWifi()">Save and connect</button><button class="danger" onclick="forgetWifi()">Forget Wi-Fi and start SoftAP</button></div><div class="notice" id="wifiMessage" role="status" aria-live="polite">Select a 2.4 GHz Wi-Fi network.</div><div id="adminSetup" class="card" style="display:none;margin-top:16px"><h2>Create administrator</h2><p class="muted">Wi-Fi connected. Secure device administration before leaving SoftAP.</p><div class="field"><label>Administrator username</label><input id="newAdminUser" value="admin" autocomplete="username"></div><div class="field"><label>Administrator password (minimum 12 characters)</label><input id="newAdminPass" type="password" autocomplete="new-password"></div><div class="field"><label>Confirm password</label><input id="newAdminConfirm" type="password" autocomplete="new-password"></div><button class="primary" id="createAdminBtn" onclick="createAdmin()">Create administrator y finalizar</button><div class="notice" id="adminMessage" role="status"></div></div></div></div></section>
<section id="system" class="view"><div class="card"><h2>Device information</h2><div id="systemFacts"></div><div class="panelactions" style="margin-top:20px"><button onclick="restartDevice()">Restart ESP32</button><button onclick="showView('diagnostics')">View diagnostics</button></div><div class="notice">Firmware de mantenimiento. Al cargar otro firmware en el ESP32, las templates almacenadas en el AS608 permanecen intactas.</div></div></section>
<section id="connections" class="view"><div class="card"><h2>Connections e integraciones</h2><p class="muted">Future integration design. The AS608 core remains independent of external systems.</p><div class="kv"><span>REST Management API</span><span class="green">Local · </span></div><div class="kv"><span>Webhook HTTP</span><span class="muted">Planned</span></div><div class="kv"><span>MQTT</span><span class="muted">Planned</span></div><div class="kv"><span>Odoo / PowerGym</span><span class="muted">Future adapter</span></div><div class="notice">No external connections are active. Sensor operations remain local.</div></div></section>
</main></div><script>
const $=id=>document.getElementById(id);let state=null,selected=0,busy=false,authHeader="",deviceMode=null;
const titles={status:['Sensor status','Real-time AS608 information'],prints:['Fingerprints','Ciclo de vida de templates biométricas'],identify:['Identify','Reconocimiento local de fingerprints'],diagnostics:['Diagnostics','Technical status and export'],wifi:['Wi-Fi','Connectivity y provisioning'],system:['System','ESP32 configuration'],connections:['Connections','External integrations and protocols']};
function showView(name){$('refreshBtn').hidden=name==='identify';document.querySelectorAll('.view').forEach(e=>e.classList.toggle('active',e.id===name));document.querySelectorAll('[data-view]').forEach(e=>e.classList.toggle('active',e.dataset.view===name));$('heading').textContent=titles[name][0];$('subtitle').textContent=titles[name][1]}
document.querySelectorAll('[data-view]').forEach(e=>e.onclick=()=>showView(e.dataset.view));
async function api(path,method='GET',data){let opts={method,headers:{}};if(authHeader)opts.headers['Authorization']=authHeader;if(data){opts.headers['Content-Type']='application/x-www-form-urlencoded';opts.body=new URLSearchParams(data)}let r=await fetch(path,opts);let txt=await r.text();let parsed;try{parsed=JSON.parse(txt)}catch{parsed={error:txt}}if(!r.ok)throw Error((r.status===401?'Invalid administrator credentials. ': '')+(parsed.error||r.statusText));return parsed}
function fact(a,b){let el=document.createElement('div');el.className='kv';let l=document.createElement('span');l.textContent=a;let r=document.createElement('span');r.textContent=String(b);el.append(l,r);return el}
function render(){if(!state)return;let s=state.sensor,w=state.wifi,x=state.system;$('cap').textContent=s.capacity;$('count').textContent=s.count;$('free').textContent=s.free;$('level').textContent=s.securityLevel;$('touch').textContent=s.touch?'FINGER':'SIN FINGER';$('online').textContent=s.connected?'Connected':'Disconnected';$('online').className='pill '+(s.connected?'green':'red');$('printTotal').textContent=s.count+' IDs';$('sidebarInfo').textContent=(s.connected?'AS608: Connected':'AS608: Offline')+' · '+w.ip+' · '+Math.floor(x.uptime/60)+' min';$('facts').replaceChildren(fact('Model','AS608 compatible'),fact('Connected',s.connected?'Yes':'No'),fact('Capacity',s.capacity),fact('Enrolled',s.count),fact('Available',s.free),fact('Security level',s.securityLevel),fact('Touch GPIO4',s.touch?'FINGER':'SIN FINGER'),fact('UART','57600 baud'));
$('health').replaceChildren(fact('Sensor AS608',s.connected?'OK':'ERROR'),fact('Memory map',state.index.valid?'OK':'ERROR'),fact('Consistency',state.index.valid&&state.index.occupiedCount===s.count?'OK':'CHECK'),fact('Wi-Fi',w.mode),fact('ESP32','OK'));$('wifiFacts').replaceChildren(fact('Mode',w.mode),fact('SSID',w.ssid),fact('IP',w.ip),fact('MAC',w.mac),fact('RSSI',w.staConnected?w.rssi+' dBm':'N/A (no STA)'),fact('IP LAN',w.staIp),fact('IP SoftAP',w.apIp),fact('Hostname','as608-manager.local'));$('systemFacts').replaceChildren(fact('Firmware','AS608 Manager'),fact('Uptime',x.uptime+' seconds'),fact('Free heap',x.heap+' bytes'),fact('Chip',x.chip),fact('Touch',s.touch?'Detected':'Sin dedo'));
$('json').textContent=JSON.stringify(state,null,2);$('occupiedList').textContent=state.index.valid?(state.index.ids.length?state.index.ids.join(', '):'Sin templates'):'Memory map unavailable';$('mapMessage').textContent=state.index.valid?'Index verified':state.index.error;drawSlots()}
function drawSlots(){if(!state)return;let cap=state.sensor.capacity;let page=Number($('page').value);let start=page*100;let holder=$('slots');holder.replaceChildren();for(let id=start;id<Math.min(start+100,cap);id++){let btn=document.createElement('button');btn.className='slot'+(state.index.ids.includes(id)?' used':'')+(id===selected?' selected':'');btn.title='ID '+id;btn.textContent=state.index.ids.includes(id)?id:'';btn.onclick=()=>{selected=id;$('printId').value=id;drawSlots()};holder.append(btn)}$('selectedId').textContent='ID '+selected;$('selectedInfo').textContent=state.index.valid?(state.index.ids.includes(selected)?'Occupied template':'Free slot'):'Inventory unavailable'}
async function refresh(){if(busy)return;busy=true;try{state=await api('/api/status');render()}catch(e){$('sidebarInfo').textContent='Error: '+e.message}finally{busy=false}}
async function scanNetworks(){$('networks').textContent='Scanning...';try{let d=await api('/api/networks');$('networks').replaceChildren();d.networks.forEach(n=>{let b=document.createElement('button');b.textContent=n.ssid+' ('+n.rssi+' dBm)';b.style.margin='4px';b.onclick=()=>{$('ssid').value=n.ssid};$('networks').append(b)})}catch(e){$('networks').textContent=e.message}}
let wifiPoll=null;
async function saveWifi(){
  let ssid=$('ssid').value.trim(),password=$('password').value;
  if(!ssid){$('wifiMessage').textContent='Enter the SSID';return}
  $('saveWifiBtn').disabled=true;
  $('wifiMessage').textContent='Connecting...';
  try{
    await api('/api/wifi','POST',{ssid,password});
    $('password').value='';
    if(wifiPoll)clearInterval(wifiPoll);
    wifiPoll=setInterval(checkWifiProgress,1200);
    await checkWifiProgress();
  }catch(e){$('wifiMessage').textContent='Error: '+e.message;$('saveWifiBtn').disabled=false}
}
async function checkWifiProgress(){
  try{
    let d=await api('/api/wifi/progress');
    $('wifiMessage').textContent=d.message; if(d.ip)window.lastWifiIP=d.ip;
    if(d.state==='connected'){
      clearInterval(wifiPoll);wifiPoll=null;
      $('wifiMessage').textContent='✓ '+d.message+' · When the AP disconnects, connect your phone to the same network and open http://'+d.ip+'/';
      $('saveWifiBtn').disabled=false;
      if(deviceMode && !deviceMode.adminConfigured){$('adminSetup').style.display='block';$('wifiMessage').textContent='✓ Wi-Fi connected. Create an administrator before leaving SoftAP.';}
    }else if(d.state==='error'){
      clearInterval(wifiPoll);wifiPoll=null;$('saveWifiBtn').disabled=false;
    }
  }catch(e){$('wifiMessage').textContent='Device not responding: '+e.message;clearInterval(wifiPoll);wifiPoll=null;$('saveWifiBtn').disabled=false}
}
async function createAdmin(){
 let username=$('newAdminUser').value.trim(),password=$('newAdminPass').value;
 if(password!==$('newAdminConfirm').value){$('adminMessage').textContent='Passwords do not match';return}
 $('createAdminBtn').disabled=true;
 try{let d=await api('/api/admin/setup','POST',{username,password});$('adminMessage').textContent=d.message+' · IP: '+(window.lastWifiIP||'check the serial monitor')+' · Connect your phone to the regular Wi-Fi network.'; $('newAdminPass').value='';$('newAdminConfirm').value='';}
 catch(e){$('adminMessage').textContent='Error: '+e.message;$('createAdminBtn').disabled=false}
}
async function forgetWifi(){if(!confirm('Delete Wi-Fi credentials and restart in SoftAP mode?'))return;try{await api('/api/wifi/reset','POST');alert('Restarting in SoftAP mode. Connect to AS608-Manager-Setup')}catch(e){alert(e.message)}}
async function restartDevice(){if(!confirm('¿Restart ESP32?'))return;try{await api('/api/restart','POST')}catch(e){alert(e.message)}}
async function startJob(type){let id=Number($('printId').value);if(type==='enroll'&&(!Number.isInteger(id)||id<0||!state||id>=state.sensor.capacity)){alert('ID out of range');return}try{let d=await api('/api/job/start','POST',{type,id});$('jobState').textContent=d.message;$('identifyState').textContent=d.message;showView(type==='enroll'?'prints':'identify')}catch(e){alert(e.message)}}
async function cancelJob(){try{let d=await api('/api/job/cancel','POST');$('jobState').textContent=d.message;$('identifyState').textContent=d.message}catch(e){alert(e.message)}}
async function deleteOne(){let id=Number($('printId').value);if(!Number.isInteger(id)||id<0||!state||id>=state.sensor.capacity){alert('Invalid ID');return}if(!confirm('Permanently delete template ID '+id+'?'))return;try{let d=await api('/api/fingerprint/delete','POST',{id});alert(d.message);await refresh()}catch(e){alert(e.message)}}
async function clearAll(){if(!confirm('ATENCIÓN: se borrarán TODAS las templates del AS608. ¿Continuar?'))return;let v=prompt('Type DELETE ALL to confirm:');if(v!=='DELETE ALL')return;try{let d=await api('/api/fingerprint/clear','POST',{confirm:v});alert(d.message);await refresh()}catch(e){alert(e.message)}}
function exportJSON(){if(!state)return;let b=new Blob([JSON.stringify(state,null,2)],{type:'application/json'});let u=URL.createObjectURL(b);let a=document.createElement('a');a.href=u;a.download='as608-diagnostic.json';a.click();URL.revokeObjectURL(u)}
const LIVE_TTL_MS=5000;
let liveSeq=-1, liveWasScanning=false, liveExpired=false;
function clearLiveResult(){
  $('liveTitle').textContent='Waiting for fingerprint';
  $('liveDescription').textContent='Place your finger on the AS608 sensor';
  $('liveId').textContent='';
  $('liveConfidence').textContent='—';
  $('liveLatency').textContent='—';
  $('liveCapture').textContent='Capture —';
  $('liveConvert').textContent='Conversion —';
  $('liveSearch').textContent='Search —';
  $('liveBreakdown').hidden=true;
  $('fingerOrb').className='finger-orb';
  $('liveFooter').textContent='Ready to detect another finger';
}
async function pollLive(){
  if(!authHeader || !deviceMode || !deviceMode.adminConfigured)return;
  try{
    const d=await api('/api/live');
    const scanning=d.status==='scanning';
    const fresh=d.sequence>0 && d.ageMs<LIVE_TTL_MS;
    if(!scanning && !fresh){
      if(!liveExpired || liveWasScanning)clearLiveResult();
      liveExpired=true;liveWasScanning=false;liveSeq=d.sequence;
      return;
    }
    if(!scanning && d.sequence===liveSeq && !liveWasScanning && !liveExpired)return;
    liveExpired=false;liveWasScanning=scanning;liveSeq=d.sequence;
    const titles={waiting:'Waiting for fingerprint',scanning:'Identifying...',matched:'Fingerprint identified',not_found:'No match',error:'Read error',no_finger:'No image'};
    $('liveTitle').textContent=titles[d.status]||d.status;
    $('liveDescription').textContent=d.detail;
    $('liveId').textContent=d.status==='matched'?'ID #'+String(d.id).padStart(3,'0'):'';
    $('liveConfidence').textContent=d.status==='matched'?d.confidence:'—';
    $('liveLatency').textContent=scanning?'In progress':d.totalMs+' ms';
    $('liveCapture').textContent='Capture '+d.captureMs+' ms';
    $('liveConvert').textContent='Conversion '+d.convertMs+' ms';
    $('liveSearch').textContent='Search '+d.searchMs+' ms';
    $('liveBreakdown').hidden=scanning;
    $('liveFirstImage').textContent=d.firstImageMs+' ms';
    $('liveAttempts').textContent=d.captureAttempts;
    $('liveRetries').textContent=d.noFingerRetries;
    $('liveImageCalls').textContent=d.imageCallMs+' ms';
    $('liveOverhead').textContent=Math.max(0,d.totalMs-d.captureMs-d.convertMs-d.searchMs)+' ms';
    $('fingerOrb').className='finger-orb '+d.status;
    $('liveFooter').textContent=scanning?'Capturendo imagen':(d.touch?'Remove your finger to allow another scan':'Ready to detect another finger');
  }catch(e){$('liveDescription').textContent=e.message}
}
async function pollJob(){try{let d=await api('/api/job');$('jobState').textContent=d.message;$('identifyState').textContent=d.message;if(d.status==='done'||d.status==='error')await refresh()}catch(e){}}
(async()=>{
 try{deviceMode=await api('/api/mode');}catch(e){$('sidebarInfo').textContent=e.message;return}
 if(deviceMode.setup && !deviceMode.adminConfigured){
   document.querySelectorAll('[data-view]').forEach(b=>{if(b.dataset.view!=='wifi')b.style.display='none'});
   showView('wifi');$('wifiMessage').textContent='Step 1 of 2: connect the ESP32 to Wi-Fi. Then create the administrator.';
   scanNetworks();
   return;
 }
 let username=prompt('Administrator username');
 let password=prompt('Contraseña administrativa');
 if(!username || !password){$('sidebarInfo').textContent='Sign in to manage the device';return}
 authHeader='Basic '+btoa(unescape(encodeURIComponent(username+':'+password)));
 await refresh();
 if(deviceMode.setup){showView('wifi');scanNetworks()}
 setInterval(refresh,7000);setInterval(pollJob,1000);setInterval(pollLive,300);pollLive();
})().catch(e=>{$('sidebarInfo').textContent='Error: '+e.message});
</script></body></html>
)PAGE";

bool requireAdmin() {
  if (!adminConfigured) {
    server.send(403, "application/json", "{\"error\":\"Configura primero el administrador desde el SoftAP\"}");
    return false;
  }
  if (server.authenticate(adminUser.c_str(), adminPassword.c_str())) return true;
  server.requestAuthentication();
  return false;
}
bool onSetupAP() {
  // Provisioning must originate from the SoftAP interface, not the LAN.
  return setupMode && server.client().localIP() == WiFi.softAPIP();
}
void handleAdminSetup() {
  if (!onSetupAP() || adminConfigured || wifiState != "connected") {
    server.send(403, "application/json", "{\"error\":\"Initial setup unavailable\"}");
    return;
  }
  String user = server.arg("username"), password = server.arg("password");
  user.trim();
  if (user.length() < 3 || user.length() > 32 || password.length() < 12 || password.length() > 64) {
    server.send(400, "application/json", "{\"error\":\"Username: 3-32 characters; password: 12-64 characters\"}");
    return;
  }
  if (!securityPrefs.putString("user", user) || !securityPrefs.putString("pass", password)) {
    server.send(500, "application/json", "{\"error\":\"No se pudieron guardar las credenciales\"}");
    return;
  }
  adminUser = user; adminPassword = password; adminConfigured = true;
  wifiRestartAt = millis() + 10000;
  Serial.println("[Security] Admin configured; restarting in 10 seconds");
  server.send(200, "application/json", "{\"message\":\"Administrador creado; reiniciando en 10 seconds\"}");
}
void jsonResponse(const String& s, int code) { server.send(code,"application/json; charset=utf-8",s); }
String escapeJson(String s) { s.replace("\\","\\\\");s.replace("\"","\\\"");s.replace("\n","\\n");s.replace("\r","\\r");return s; }
void errorResponse(String s, int code=400) { jsonResponse("{\"error\":\""+escapeJson(s)+"\"}",code); }
void clearIndex(){memset(bitmap,0,sizeof(bitmap));occupiedCount=0;indexValid=false;}

bool readIndexPage(uint8_t page){
  uint8_t cmd[]={0x1F,page};
  Adafruit_Fingerprint_Packet req(FINGERPRINT_COMMANDPACKET,4,cmd);
  sensor.writeStructuredPacket(req);
  uint8_t respData[64]={0};
  Adafruit_Fingerprint_Packet resp(FINGERPRINT_ACKPACKET,sizeof(respData),respData);
  if(sensor.getStructuredPacket(&resp,1000)!=FINGERPRINT_OK){lastError="Timeout index page "+String(page);return false;}
  if(resp.type!=FINGERPRINT_ACKPACKET||resp.length<35||resp.data[0]!=FINGERPRINT_OK){lastError="Invalid index page "+String(page);return false;}
  memcpy(bitmap+page*32,resp.data+1,32);return true;
}
void refreshSensor(){
  lastError="";sensorOnline=sensor.verifyPassword();
  if(!sensorOnline){lastError="AS608 not responding";sensorCapacity=templateCount=0;clearIndex();return;}
  if(sensor.getParameters()!=FINGERPRINT_OK){lastError="Error reading parameters";clearIndex();return;}
  sensorCapacity=sensor.capacity;securityLevel=sensor.security_level;
  if(sensor.getTemplateCount()!=FINGERPRINT_OK){lastError="Error reading template count";clearIndex();return;}
  templateCount=sensor.templateCount;clearIndex();
  if(sensorCapacity==0||sensorCapacity>512){lastError="Capacity no soportada";return;}
  uint8_t pages=(sensorCapacity+255)/256;
  for(uint8_t p=0;p<pages;p++)if(!readIndexPage(p)){clearIndex();return;}
  for(uint16_t id=0;id<sensorCapacity;id++)if(bitmap[id/8]&(1<<(id%8)))occupiedCount++;
  indexValid=true;
  if(occupiedCount!=templateCount)lastError="Count and indexes do not match";
}

void stopJob(String status,String message){job=JOB_NONE;jobResult=status;jobMessage=message;lastEvent=message;}
void runJob(){
  if(job==JOB_NONE)return;
  if(millis()-jobStarted>45000){stopJob("error","Tiempo agotado (45s)");return;}
  if(millis()-lastPoll<150)return;
  lastPoll=millis();
  uint8_t r;
  if(job==JOB_IDENTIFY){
    if(!digitalRead(PIN_TOUCH)){jobMessage="Coloca el dedo en el sensor";return;}
    r=sensor.getImage();if(r==FINGERPRINT_NOFINGER)return;
    if(r!=FINGERPRINT_OK){stopJob("error","Error capturing image: "+String(r));return;}
    r=sensor.image2Tz(1);if(r!=FINGERPRINT_OK){stopJob("error","Error processing fingerprint: "+String(r));return;}
    r=sensor.fingerFastSearch();
    if(r==FINGERPRINT_OK)stopJob("done","Coincidencia ID "+String(sensor.fingerID)+" · confianza "+String(sensor.confidence));
    else if(r==FINGERPRINT_NOTFOUND)stopJob("done","Fingerprint not registered");
    else stopJob("error","Search error: "+String(r));
    return;
  }
  if(job==JOB_ENROLL){
    if(jobStage==0){
      jobMessage="Paso 1/3: coloca el dedo";
      if(!digitalRead(PIN_TOUCH))return;
      r=sensor.getImage();if(r==FINGERPRINT_NOFINGER)return;
      if(r!=FINGERPRINT_OK){stopJob("error","Error capturing first image: "+String(r));return;}
      r=sensor.image2Tz(1);if(r!=FINGERPRINT_OK){stopJob("error","First template error: "+String(r));return;}
      jobStage=1;jobMessage="Paso 2/3: retira el dedo";return;
    }
    if(jobStage==1){
      if(digitalRead(PIN_TOUCH))return;
      // Confirm image engine has also observed removal.
      if(sensor.getImage()!=FINGERPRINT_NOFINGER)return;
      jobStage=2;jobMessage="Paso 3/3: coloca el mismo dedo otra vez";return;
    }
    if(jobStage==2){
      if(!digitalRead(PIN_TOUCH))return;
      r=sensor.getImage();if(r==FINGERPRINT_NOFINGER)return;
      if(r!=FINGERPRINT_OK){stopJob("error","Error capturing second image: "+String(r));return;}
      r=sensor.image2Tz(2);if(r!=FINGERPRINT_OK){stopJob("error","Second template error: "+String(r));return;}
      r=sensor.createModel();if(r!=FINGERPRINT_OK){stopJob("error","Fingerprints no coinciden o error de modelo: "+String(r));return;}
      r=sensor.storeModel(jobId);
      if(r==FINGERPRINT_OK)stopJob("done","Fingerprint saved at ID "+String(jobId));
      else stopJob("error","Error saving ID "+String(jobId)+": "+String(r));
      return;
    }
  }
}

void handleStatus(){
  if(job==JOB_NONE)refreshSensor();
  String j;j.reserve(2800);
  j="{\"sensor\":{\"connected\":"+String(sensorOnline?"true":"false")+
    ",\"capacity\":"+String(sensorCapacity)+",\"count\":"+String(templateCount)+
    ",\"free\":"+String(sensorCapacity>=templateCount?sensorCapacity-templateCount:0)+
    ",\"securityLevel\":"+String(securityLevel)+",\"touch\":"+String(digitalRead(PIN_TOUCH)?"true":"false")+"},";
  j+="\"index\":{\"valid\":"+String(indexValid?"true":"false")+
    ",\"occupiedCount\":"+String(occupiedCount)+",\"ids\":[";
  bool first=true;
  if(indexValid)for(uint16_t id=0;id<sensorCapacity;id++)if(bitmap[id/8]&(1<<(id%8))){if(!first)j+=",";j+=String(id);first=false;}
  j+="],\"error\":\""+escapeJson(lastError)+"\"},";
  const wifi_mode_t actualMode = WiFi.getMode();
  const bool apActive = (actualMode & WIFI_AP) != 0;
  const bool staConnected = (actualMode & WIFI_STA) && WiFi.status() == WL_CONNECTED;
  const String modeName = apActive && staConnected ? "AP+STA (provisioning)" :
                          apActive ? "SoftAP" : staConnected ? "Station" : "Disconnected";
  const String primarySsid = staConnected ? WiFi.SSID() : apActive ? String(AP_SSID) : String("-");
  const String primaryIp = staConnected ? WiFi.localIP().toString() : apActive ? WiFi.softAPIP().toString() : String("-");
  j+="\"wifi\":{\"mode\":\""+modeName+
    "\",\"ssid\":\""+escapeJson(primarySsid)+
    "\",\"ip\":\""+primaryIp+
    "\",\"mac\":\""+WiFi.macAddress()+"\",\"rssi\":"+String(staConnected?WiFi.RSSI():0)+
    ",\"staConnected\":"+String(staConnected?"true":"false")+
    ",\"apActive\":"+String(apActive?"true":"false")+
    ",\"staIp\":\""+(staConnected?WiFi.localIP().toString():String("-"))+
    "\",\"apIp\":\""+(apActive?WiFi.softAPIP().toString():String("-"))+"\"},";
  j+="\"system\":{\"uptime\":"+String(millis()/1000)+",\"heap\":"+String(ESP.getFreeHeap())+
    ",\"chip\":\""+escapeJson(ESP.getChipModel())+"\",\"lastEvent\":\""+escapeJson(lastEvent)+"\"}}";
  jsonResponse(j);
}
void handleNetworks(){
  if(!setupMode && !requireAdmin())return;
  int n=WiFi.scanNetworks();String j="{\"networks\":[";
  for(int i=0;i<n;i++){if(i)j+=",";j+="{\"ssid\":\""+escapeJson(WiFi.SSID(i))+"\",\"rssi\":"+String(WiFi.RSSI(i))+"}";}
  WiFi.scanDelete();j+="]}";jsonResponse(j);
}
void handleWifi(){
  if (!adminConfigured && !onSetupAP()) return errorResponse("Usa el SoftAP para configurar Wi-Fi",403);
  if(wifiPending)return errorResponse("Connection in progress",409);
  String ssid=server.arg("ssid"), pass=server.arg("password");
  if(ssid.isEmpty()||ssid.length()>32)return errorResponse("SSID invalido");
  wifiTarget=ssid;wifiPassword=pass;wifiPending=true;wifiStarted=millis();
  wifiState="connecting";wifiDetail="Conectando a "+ssid;wifiNewIP="";
  // AP+STA is allowed ONLY while provisioning, to keep the setup page reachable.
  // Reconfiguring from LAN must never open an unsolicited setup access point.
  WiFi.mode(setupMode ? WIFI_AP_STA : WIFI_STA);
  WiFi.begin(wifiTarget.c_str(),wifiPassword.c_str());
  Serial.printf("[WiFi] Connecting to %s\n",wifiTarget.c_str());
  jsonResponse("{\"state\":\"connecting\",\"message\":\"Connection started\"}",202);
}
void handleWifiProgress(){
  String j="{\"state\":\""+escapeJson(wifiState)+"\",\"message\":\""+escapeJson(wifiDetail)+"\",\"ip\":\""+escapeJson(wifiNewIP)+"\"}";
  jsonResponse(j);
}
void processWifi(){
  if(wifiPending){
    if(WiFi.status()==WL_CONNECTED){
      wifiNewIP=WiFi.localIP().toString();
      size_t a=prefs.putString("ssid",wifiTarget),b=prefs.putString("password",wifiPassword);
      wifiPassword="";
      wifiPending=false;
      if(a==0||b==0){wifiState="error";wifiDetail="Connected, pero no se pudo guardar en NVS";Serial.println("[WiFi] NVS save failed");return;}
      wifiState="connected";wifiDetail="Connected. IP: "+wifiNewIP+". The device will restart";
      Serial.printf("[WiFi] Connected, IP: %s; restarting soon\n",wifiNewIP.c_str());
      if(adminConfigured) wifiRestartAt=millis()+10000;
    }else if(millis()-wifiStarted>20000){
      int status=WiFi.status();wifiPending=false;wifiPassword="";
      wifiState="error";wifiDetail="No se pudo conectar (status "+String(status)+"). Revisa SSID, clave y red 2.4 GHz";
      Serial.printf("[WiFi] Failed, status: %d\n",status);
      if(setupMode)WiFi.disconnect(false,false);
    }
  }
  if(wifiRestartAt && (int32_t)(millis()-wifiRestartAt)>=0){
    Serial.println("[WiFi] Restarting into station mode");Serial.flush();ESP.restart();
  }
}
void handleWifiReset(){prefs.remove("ssid");prefs.remove("password");jsonResponse("{\"message\":\"Reiniciando en SoftAP\"}");delay(400);ESP.restart();}
void handleJobStart(){
  if(job!=JOB_NONE)return errorResponse("Otra operacion esta en curso",409);
  if(!sensorOnline||!indexValid)return errorResponse("Sensor o inventario no disponible",503);
  String type=server.arg("type");
  if(type!="identify"&&type!="enroll")return errorResponse("Tipo invalido");
  if(type=="enroll"){
    String idText=server.arg("id");
    if(idText.isEmpty())return errorResponse("ID requerido");
    for(size_t i=0;i<idText.length();i++)if(!isDigit(idText[i]))return errorResponse("ID invalido");
    long id=idText.toInt();if(id<0||id>=sensorCapacity)return errorResponse("ID out of range");
    if(bitmap[id/8]&(1<<(id%8)))return errorResponse("ID ocupado; no se sobrescribira",409);
    jobId=id;
  }
  job=(type=="identify")?JOB_IDENTIFY:JOB_ENROLL;jobStage=0;jobStarted=millis();lastPoll=0;
  jobResult="running";jobMessage=type=="identify"?"Coloca el dedo":"Paso 1/3: coloca el dedo";
  jsonResponse("{\"message\":\""+escapeJson(jobMessage)+"\"}");
}
void handleJob(){jsonResponse("{\"status\":\""+jobResult+"\",\"message\":\""+escapeJson(jobMessage)+"\"}");}
void handleDelete(){
  if(job!=JOB_NONE)return errorResponse("Operacion en curso",409);
  if(!sensorOnline||!indexValid)return errorResponse("Inventory unavailable",503);
  String s=server.arg("id");if(s.isEmpty())return errorResponse("ID requerido");
  for(size_t i=0;i<s.length();i++)if(!isDigit(s[i]))return errorResponse("ID invalido");
  long id=s.toInt();if(id<0||id>=sensorCapacity)return errorResponse("ID out of range");
  if(!(bitmap[id/8]&(1<<(id%8))))return errorResponse("ID libre",409);
  uint8_t r=sensor.deleteModel(id);
  if(r!=FINGERPRINT_OK)return errorResponse("Deletion error: "+String(r),500);
  lastEvent="Deleted template ID "+String(id);refreshSensor();
  jsonResponse("{\"message\":\"Template deleted\"}");
}
void handleClear(){
  if(job!=JOB_NONE)return errorResponse("Operacion en curso",409);
  if(!sensorOnline)return errorResponse("Sensor disconnected",503);
  if(server.arg("confirm")!="DELETE ALL")return errorResponse("Confirmacion requerida");
  uint8_t r=sensor.emptyDatabase();if(r!=FINGERPRINT_OK)return errorResponse("Memory erase error: "+String(r),500);
  lastEvent="Biometric memory erased";refreshSensor();jsonResponse("{\"message\":\"Biometric memory erased\"}");
}
void startAP(){
  setupMode=true;
  // Stop any previous STA session (including Arduino Wi-Fi auto-restore).
  WiFi.disconnect(true, false);
  WiFi.mode(WIFI_AP);
  if(!WiFi.softAP(AP_SSID,AP_PASSWORD)) Serial.println("[WiFi] ERROR starting SoftAP");
  dns.start(53,"*",WiFi.softAPIP());
  Serial.println("=== SETUP MODE ===");Serial.println(String("SSID: ")+AP_SSID);
  Serial.println(String("URL: http://")+WiFi.softAPIP().toString());
}
void setupWifi(){
  prefs.begin("as608-wifi",false);
  securityPrefs.begin("as608-admin",false);
  adminUser=securityPrefs.getString("user","");
  adminPassword=securityPrefs.getString("pass","");
  adminConfigured=!adminUser.isEmpty() && !adminPassword.isEmpty();
  Serial.printf("[Security] Admin configured: %s\n",adminConfigured?"yes":"no");
  String ssid=prefs.getString("ssid","");
  String pass=prefs.getString("password","");
  Serial.printf("[WiFi] Stored SSID: %s\n",ssid.isEmpty()?"(none)":ssid.c_str());

  // Never trust an inherited WL_CONNECTED from the radio's persisted state.
  // Start from a known disabled state and explicitly choose one operating mode.
  WiFi.mode(WIFI_OFF);
  if(!ssid.isEmpty() && adminConfigured){
    WiFi.mode(WIFI_STA);
    WiFi.begin(ssid.c_str(),pass.c_str());
    uint32_t start=millis();
    while(WiFi.status()!=WL_CONNECTED && millis()-start<15000) delay(150);
    if(WiFi.status()==WL_CONNECTED){
      setupMode=false;
      if(!MDNS.begin(HOSTNAME)) Serial.println("[mDNS] Startup failed");
      Serial.println("=== WIFI CONNECTED: STA ONLY ===");
      Serial.println("IP: "+WiFi.localIP().toString());
      Serial.println(String("URL: http://")+HOSTNAME+".local");
      return;
    }
    Serial.printf("[WiFi] Station failed, status=%d; switching to SoftAP only\n",WiFi.status());
  }else{
    Serial.println("[WiFi] Setup incomplete; starting SoftAP only");
  }
  startAP();
}
void setupWeb(){
  server.on("/",HTTP_GET,[]{server.send_P(200,"text/html; charset=utf-8",HTML);});
  server.on("/api/mode",HTTP_GET,[]{jsonResponse(String("{\"setup\":")+(setupMode?"true":"false")+",\"adminConfigured\":"+(adminConfigured?"true":"false")+"}");});
  server.on("/api/admin/setup",HTTP_POST,handleAdminSetup);
  server.on("/api/status",HTTP_GET,[]{if(requireAdmin())handleStatus();});
  server.on("/api/networks",HTTP_GET,handleNetworks);
  server.on("/api/wifi",HTTP_POST,[]{if((setupMode && !adminConfigured && onSetupAP()) || requireAdmin())handleWifi();});
  server.on("/api/wifi/progress",HTTP_GET,[]{if((setupMode && !adminConfigured && onSetupAP()) || requireAdmin())handleWifiProgress();});
  server.on("/api/wifi/reset",HTTP_POST,[]{if(requireAdmin())handleWifiReset();});
  server.on("/api/restart",HTTP_POST,[]{if(!requireAdmin())return;jsonResponse("{\"message\":\"Reiniciando\"}");delay(400);ESP.restart();});
  server.on("/api/job/start",HTTP_POST,[]{if(requireAdmin())handleJobStart();});
  server.on("/api/job",HTTP_GET,[]{if(requireAdmin())handleJob();});
  server.on("/api/live",HTTP_GET,[]{if(requireAdmin())handleLive();});
  server.on("/api/job/cancel",HTTP_POST,[]{if(!requireAdmin())return;stopJob("idle","Operacion cancelada");jsonResponse("{\"message\":\"Operacion cancelada\"}");});
  server.on("/api/fingerprint/delete",HTTP_POST,[]{if(requireAdmin())handleDelete();});
  server.on("/api/fingerprint/clear",HTTP_POST,[]{if(requireAdmin())handleClear();});
  server.onNotFound([](){if(setupMode){server.sendHeader("Location","http://192.168.4.1/");server.send(302,"text/plain","");}else server.send(404,"text/plain","Not found");});
  server.begin();Serial.println("HTTP server ready");
}
void setup(){
  Serial.begin(115200);delay(600);Serial.println("\n=== AS608 MANAGER ===");
  pinMode(PIN_TOUCH,INPUT);sensorUart.begin(SENSOR_BAUD,SERIAL_8N1,PIN_RX,PIN_TX);
  refreshSensor();Serial.printf("AS608: %s, capacity: %u, count: %u, occupied: %u\n",sensorOnline?"OK":"ERROR",sensorCapacity,templateCount,occupiedCount);
  setupWifi();setupWeb();
}
void loop(){if(setupMode)dns.processNextRequest();server.handleClient();processWifi();runJob();processLive();delay(2);}