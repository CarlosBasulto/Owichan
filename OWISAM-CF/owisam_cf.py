# Diccionario para guardar redes únicas
networks = {}

def change_to_monitor(interface):
    print("[*] Cambiando interfaz a modo monitor...")
    subprocess.call(["ip", "link", "set", interface, "down"])
    subprocess.call(["iwconfig", interface, "mode", "monitor"])
    subprocess.call(["ip", "link", "set", interface, "up"])
    print("[+] Interfaz en modo monitor.")

def packet_handler(pkt):
    if pkt.haslayer(Dot11Beacon):
        ssid = pkt[Dot11Elt].info.decode(errors="ignore")
        bssid = pkt[Dot11].addr2
        stats = pkt[Dot11Beacon].network_stats()
        channel = stats.get("channel")

        if bssid not in networks:
            networks[bssid] = {
                "SSID": ssid,
                "Channel": channel,
                "Weak_Config": analyze_weak_config(ssid, channel)
            }

def analyze_weak_config(ssid, channel):
    reasons = []
    if any(default in ssid.upper() for default in default_ssids):
        reasons.append("SSID por defecto")
    if str(channel) == "6":
        reasons.append("Canal 6 saturado")
    return reasons

def generate_report():
    now = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"reporte_owisam_cf_{now}.txt"
    with open(filename, "w") as f:
        for bssid, data in networks.items():
            f.write(f"BSSID: {bssid}\n")
            f.write(f"SSID: {data['SSID']}\n")
            f.write(f"Canal: {data['Channel']}\n")
            f.write(f"Configuraciones débiles: {', '.join(data['Weak_Config']) if data['Weak_Config'] else 'Ninguna'}\n")
            f.write("="*40 + "\n")
    print(f"\n[+] Reporte generado: {filename}")

def main():
    interface = input(">> Ingresa el nombre de tu interfaz Wi-Fi (modo monitor): ").strip()
    change_to_monitor(interface)
    print("[*] Escaneando redes... presiona Ctrl+C para detener.")
    try:
        sniff(iface=interface, prn=packet_handler, timeout=60)  # 60 segundos de escaneo
    except KeyboardInterrupt:
        pass
    generate_report()

if __name__ == "__main__":
    main()
