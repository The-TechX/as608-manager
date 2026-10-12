# AS608 Manager

Standalone firmware for **ESP32 DevKit V1** and the **AS608 fingerprint sensor**, featuring a local web interface for setup, diagnostics, fingerprint enrollment, template inventory, and management.

## Hardware

| AS608 | ESP32 |
| --- | --- |
| TX | GPIO16 (RX2) |
| RX | GPIO17 (TX2) |
| Touch / Wake | GPIO4 |
| VCC / GND | Power and ground according to your module's specifications |

Sensor UART: **57600 baud**. Serial monitor: **115200 baud**.

## Installation

1. Open `AS608_Manager/AS608_Manager.ino` in Arduino IDE.
2. Select your ESP32 board and install the **Adafruit Fingerprint Sensor Library**.
3. Compile and flash the sketch.
4. On first boot, connect to the `AS608-Manager-Setup` access point and visit `http://192.168.4.1`.
5. Configure Wi-Fi and administrator credentials. Afterwards, access the device through its LAN IP address.

**When updating firmware:** disable `Erase All Flash Before Sketch Upload` to preserve credentials stored in NVS. Fingerprint templates are stored in the AS608 sensor's memory.

## Features

- Fingerprint template inventory and management.
- Enrollment and deletion of fingerprints.
- Automatic identification triggered by GPIO4.
- Capture, conversion, search, and total latency metrics.
- Visual monitoring with neutral, matched, and not-found states.
- Responsive web UI for Wi-Fi configuration and diagnostics.
- SoftAP mode for initial setup or connectivity recovery.

## Security

**Local-network prototype. Do not expose directly to the Internet.**

- The interface uses unencrypted HTTP; HTTP Basic does not protect credentials against interception.
- The initial access point uses provisioning credentials defined in the firmware. Change them before use outside a controlled environment.
- Do not connect physical access mechanisms without additional authorization and safety controls.

## Project status

Initial project without remote-system integration. Compilation and hardware validation should be performed in the target ESP32 environment.
