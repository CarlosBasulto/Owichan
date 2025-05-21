OWISAM-HS
Herramienta OWISAM-HS para pruebas sobre hotspots y portales cautivos, desarrollada en Python como parte del módulo Hacking Ético del GS de Ciberseguridad.

OWISAM-HS permite analizar la seguridad de portales cautivos y puntos de acceso públicos desde una perspectiva pasiva, sin necesidad de tarjeta de red, verificando la exposición de formularios de login y otras posibles vulnerabilidades asociadas.

Permite identificar aspectos como:

Presencia de formularios inseguros o manipulados por JavaScript

Transmisión de credenciales en portales sin HTTPS

Detección de captchas

Inclusión de iframes con contenido no cifrado

Redirecciones sospechosas

Análisis automatizado con exportación de informe en:

TXT: para revisión manual rápida

JSON: para análisis estructurado o automatización

Esta herramienta forma parte de la metodología OWISAM (Open Wireless Security Assessment Methodology) y cumple con el control OWISAM-HS (Hotspot Security).

✅ Pasos completos para usar la herramienta sin errores
bash
Copiar
Editar
# 1. Crear entorno virtual y activarlo
python3 -m venv env
source env/bin/activate

# 2. Instalar dependencias
pip install requests beautifulsoup4

# 3. Ejecutar la herramienta
python3 owisam_hs.py
📝 Notas importantes
No requiere tarjeta de red ni modo monitor. Solo conexión a internet.

Pensada para analizar portales cautivos conocidos o accesibles por URL.

Ideal para entornos educativos, laboratorios de ciberseguridad y pentesting ético controlado.
