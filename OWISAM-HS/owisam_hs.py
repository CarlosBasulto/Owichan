import requests
from bs4 import BeautifulSoup
import json
import sys
import datetime
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def analizar_portal(url):
    resultado = {
        "url": url,
        "https": url.startswith("https://"),
        "formularios": [],
        "captchas": False,
        "iframes": [],
        "redirecciones": [],
        "vulnerabilidades": []
    }

    try:
        response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Redirecciones sospechosas
        if len(response.history) > 0:
            for resp in response.history:
                resultado["redirecciones"].append(resp.url)

        # Detección de formularios
        forms = soup.find_all('form')
        if forms:
            for form in forms:
                fdata = {
                    "action": form.get('action'),
                    "method": form.get('method', 'GET').upper(),
                    "js_event": 'onsubmit' in form.attrs,
                    "campos": [],
                    "inseguro": False
                }

                inputs = form.find_all('input')
                for inp in inputs:
                    tipo = inp.get('type', 'text')
                    nombre = inp.get('name', '')
                    fdata["campos"].append({"tipo": tipo, "nombre": nombre})

                    if tipo == 'password' and not resultado["https"]:
                        fdata["inseguro"] = True
                        resultado["vulnerabilidades"].append("⚠ Transmisión de contraseña sin HTTPS")

                # Detección de formularios con JS (onsubmit o sin action real)
                if fdata["js_event"] or fdata["action"] in [None, "", "#"]:
                    resultado["vulnerabilidades"].append("⚠ Formulario manipulado por JavaScript")
                
                resultado["formularios"].append(fdata)
        else:
            resultado["vulnerabilidades"].append("❌ No se detectaron formularios")

        # Captcha
        if "captcha" in response.text.lower():
            resultado["captchas"] = True

        # iFrames
        iframes = soup.find_all('iframe')
        for iframe in iframes:
            src = iframe.get('src')
            if src:
                resultado["iframes"].append(src)
                if "http://" in src:
                    resultado["vulnerabilidades"].append("⚠ iframe con contenido no cifrado")

        return resultado

    except requests.RequestException as e:
        return {"error": str(e)}

def exportar_informe(datos, base_filename="informe_portal"):
    fecha = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    txt_filename = f"{base_filename}_{fecha}.txt"
    json_filename = f"{base_filename}_{fecha}.json"

    # Exportar a TXT
    with open(txt_filename, "w", encoding="utf-8") as f:
        f.write(f"URL Analizada: {datos.get('url')}\n")
        f.write(f"Usa HTTPS: {datos.get('https')}\n")
        f.write(f"Captchas detectados: {datos.get('captchas')}\n")
        f.write(f"Iframes:\n")
        for iframe in datos.get('iframes', []):
            f.write(f" - {iframe}\n")
        f.write(f"Redirecciones:\n")
        for redir in datos.get('redirecciones', []):
            f.write(f" - {redir}\n")
        f.write("Formularios detectados:\n")
        for form in datos.get('formularios', []):
            f.write(f" - Acción: {form['action']} | Método: {form['method']} | JS: {form['js_event']}\n")
            f.write(f"   Campos: {[campo['tipo'] for campo in form['campos']]}\n")
        f.write("Vulnerabilidades:\n")
        for vuln in datos.get('vulnerabilidades', []):
            f.write(f" - {vuln}\n")

    # Exportar a JSON
    with open(json_filename, "w", encoding="utf-8") as fjson:
        json.dump(datos, fjson, indent=4)

    print(f"\n✅ Informe guardado como:\n- {txt_filename}\n- {json_filename}")

def menu():
    while True:
        print("\n🌍 OWISAM-HS - Análisis de Portales Cautivos")
        print("1. Analizar un portal cautivo")
        print("2. Salir")
        opcion = input("Seleccione una opción: ")

        if opcion == "1":
            url = input("🔗 Ingrese la URL del portal cautivo: ").strip()
            datos = analizar_portal(url)
            if "error" in datos:
                print(f"[!] Error: {datos['error']}")
            else:
                exportar_informe(datos)
        elif opcion == "2":
            print("👋 Saliendo...")
            sys.exit()
        else:
            print("⚠ Opción no válida. Intente de nuevo.")

if __name__ == "__main__":
    menu()
