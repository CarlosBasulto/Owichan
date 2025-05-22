# OWISAM-CF - Auditoría de Configuración de Redes Wi-Fi

**OWISAM-CF** Open WiFi Security Assessment Method - Configuración Física: es una herramienta en Python que permite detectar configuraciones débiles en redes Wi-Fi basándose en el análisis pasivo de paquetes beacon. Es útil para auditorías de seguridad básicas y análisis de exposición.

## 1. Descripción

El script realiza un escaneo pasivo del espectro Wi-Fi usando una tarjeta de red en modo monitor, detecta redes cercanas y genera un informe que destaca las siguientes debilidades:

- **SSID por defecto**, como "MOVISTAR", "TP-LINK", etc.
- **Uso del canal 6**, frecuentemente saturado en muchas áreas urbanas.

## 2. Requisitos

- Kali Linux u otra distribución Linux con herramientas de auditoría.
- Python 3.
- `scapy`.
- Interfaz Wi-Fi compatible con modo monitor. Probado con Alfa AWUS036ACH.
- Controlador compatible instalado. Probado con `rtl8812au`.

## 3. Instalación

```bash
git clone https://github.com/usuario/owisam-cf.git
cd owisam-cf
python3 -m venv venv
source venv/bin/activate
pip install scapy

## 4. Uso

1. Verifica tu interfaz Wi-Fi disponible con iwconfig.

2. Ejecuta el script con permisos de administrador: sudo python3 owisam_cf.py

3. Ingresa el nombre de tu interfaz cuando se te solicite.

4. El script intentará cambiarla automáticamente a modo monitor.

5. Se realizará un escaneo de 60 segundos.

6. Al finalizar, se generará un archivo de reporte con el siguiente formato: reporte_owisam_cf_YYYYMMDD_HHMMSS.txt

## Ejemplo de salida

```bash
BSSID: 00:11:22:33:44:55
SSID: MOVISTAR_1234
Canal: 6
Configuraciones débiles: SSID por defecto, Canal 6 saturado
========================================
