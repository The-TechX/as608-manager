# AS608 Manager

Firmware independiente para **ESP32 DevKit V1** y sensor de huellas **AS608**, con interfaz web local para configuración, diagnóstico, inventario y administración de plantillas.

## Hardware

| AS608 | ESP32 |
| --- | --- |
| TX | GPIO16 (RX2) |
| RX | GPIO17 (TX2) |
| Touch / Wake | GPIO4 |
| VCC / GND | Alimentación y tierra según especificaciones de tu módulo |

UART del sensor: **57600 baud**. Monitor serie: **115200 baud**.

## Instalación

1. Abre `AS608_Manager/AS608_Manager.ino` en Arduino IDE.
2. Selecciona tu placa ESP32 e instala **Adafruit Fingerprint Sensor Library**.
3. Compila y carga el sketch.
4. En el primer inicio, conéctate al punto de acceso `AS608-Manager-Setup` y visita `http://192.168.4.1`.
5. Configura Wi-Fi y credenciales de administrador. Posteriormente, accede mediante la IP LAN del ESP32.

**Para actualizaciones:** desactiva `Erase All Flash Before Sketch Upload` para preservar las credenciales en NVS. Las plantillas biométricas residen en la memoria del AS608.

## Funcionalidades

- Inventario y administración de plantillas biométricas.
- Enrolamiento y eliminación de huellas.
- Identificación automática por señal de wake en GPIO4.
- Métricas de captura, conversión, búsqueda y latencia total.
- Monitor visual con estados neutral, reconocido y no reconocido.
- Configuración Wi-Fi y diagnóstico desde una interfaz web responsive.
- Modo SoftAP para configuración inicial o recuperación de conectividad.

## Seguridad

**Prototipo para red local confiable. No exponer directamente a Internet.**

- La interfaz utiliza HTTP sin cifrado; HTTP Basic no protege las credenciales frente a interceptación en la red.
- El punto de acceso inicial utiliza credenciales de aprovisionamiento definidas en el firmware: cámbialas antes de utilizarlo fuera de un entorno controlado.
- No conectar directamente relés o mecanismos de acceso físico sin autorización y validaciones adicionales.

## Estado

Proyecto inicial; todavía sin integración remota con sistemas externos. Las pruebas de compilación y hardware deben realizarse en el entorno ESP32 correspondiente.
