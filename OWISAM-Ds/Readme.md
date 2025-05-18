# OWISAM-DS: Auditoría DoS en redes Wi-Fi

Este script realiza una **prueba de denegación de servicio (DoS)** vía desautenticación en redes inalámbricas de forma automática e interactiva.

---

## 📜 Descripción

- Detecta automáticamente las interfaces Wi-Fi disponibles.  
- Activa el modo monitor y verifica capacidad de inyección.  
- Escanea APs y clientes en un tiempo configurable.  
- Permite elegir **modo simulación** (dry-run) o **ejecución real** de paquetes.  
- Genera informe detallado en **JSON** o **CSV** opcional.

## 🚀 Requisitos

- **Kali Linux** (o similar) con soporte 802.11 monitor/inyección.  
- **Permisos root** (necesarios para inyección de paquetes).  
- **Python 3** y **Scapy**:
  ```bash
  sudo apt update && sudo apt install python3-pip
  pip3 install scapy

## 📂 Archivos

OWISAM-DS/
└── owisam_ds.py  # Script principal


## ⚙️ Uso

1. Dar permisos:
  chmod +x OWISAM-DS/owisam_ds.py

2. Ejecutar (como root):
  sudo ./OWISAM-DS/owisam_ds.py

3.Interacción:
  -Seleccionar interfaz Wi-Fi.
  -Definir tiempo de escaneo (por defecto 15s).
  -Elegir modo simulación (s/N).
  -Indicar paquetes por par y intervalo entre envíos.
  -Opcional: generar informe (s/N) y ruta de archivo.


## 🛠️ Parámetros disponibles

--time:	Tiempo de escaneo en segundos (default 15)	--time 30

--dry-run	Simula sin enviar paquetes	--dry-run

--count	Paquetes deauth por par AP–cliente (50)	--count 100

--interval	Intervalo entre envíos en segundos (0.1)	--interval 0.05

--report	Ruta para guardar informe .json o .csv	--report report.csv


## 🔒 Advertencia legal
Este script interrumpe conexiones Wi-Fi reales. Úsalo solo en entornos controlados o con permiso expreso del propietario de la red.
