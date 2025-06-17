
 ______             _ _          _   
|  ____|           (_) |        | |  
| |__  _ __ ___  __ _ _| |  __ _ _ __  __ _| |_ _ _______ _ __ 
|  __| | '_ ` _ \ / _` | | | / _` | '_ \ / _` | | | | |_  / _ \ '__|
| |____| | | | | | (_| | | || (_| | | | | (_| | | |_| |/ /  __/ |   
|______|_| |_| |_|\__,_|_|_| \__,_|_| |_|\__,_|_|\__, /___\___|_|   
                                                  __/ |             
                                                 |___/              
    
 Desarrollado por Oduek 
 https://github.com/oduek 

--COMO INSTALAR--

pip install pyspellchecker langdetect python-whois requests beautifulsoup4

Nota: --break-system-packages (si lo solicita)

--COMO USAR--

usage: EmailAnalyzer.py [-h] [-f FILE] [--json-output JSON_OUTPUT] [--vt-api-key VT_API_KEY] [--vt-key-delete]

Analizador de correos electrónicos (.eml) para detectar phishing.

options:
  -h, --help            show this help message and exit
  -f, --file FILE       Ruta al archivo .eml que se desea analizar.
  --json-output JSON_OUTPUT
                        Ruta para guardar el reporte en formato JSON. Si no se especifica, el reporte se imprime en la consola.
  --vt-api-key VT_API_KEY
                        Tu API Key de VirusTotal. Opcional. Si la provees aquí, se usará para esta ejecución y se guardará si no hay una existente.
  --vt-key-delete       Elimina la API Key de VirusTotal guardada permanentemente y sale del script.

Ejemplo de uso:
  python EmailAnalyzer.py -f "correo_sospechoso.eml"
  python EmailAnalyzer.py -f "correo.eml" --json-output reporte.json
  python EmailAnalyzer.py -f "adjunto_malicioso.eml" --vt-api-key TU_API_KEY_VIRUSTOTAL
  python EmailAnalyzer.py --vt-key-delete # Para eliminar la API Key de VirusTotal almacenada localmente en un archivo

Cómo obtener un archivo .eml:
  - Gmail: Abre el correo -> Haz clic en los tres puntos (Más) -> 'Descargar el mensaje'.
  - Outlook: Abre el correo -> 'Archivo' -> 'Guardar como' -> Formato: 'Texto sin formato (*.eml)'.
  - ProtonMail: Usa la herramienta Proton Mail Export Tool para exportar correos en formato EML.
  - Zoho Mail: Inicia sesión -> 'Configuración' -> 'Importación/Exportación' -> Selecciona el archivo EML o ZIP con correos.
  - Yahoo Mail: Abre el correo -> Haz clic en 'Más' -> 'Ver mensaje original' -> Guarda el contenido como .eml.
  - Apple Mail: Abre el correo -> 'Archivo' -> 'Guardar como' -> Selecciona formato EML.
  - Thunderbird: Abre el correo -> 'Archivo' -> 'Guardar como' -> Formato EML

Nota: Después de un análisis exitoso, se te presentará un menú interactivo para exportar
      los resultados a diferentes formatos (TXT, HTML, XML, JSON) o todos a la vez. Si usas
      --json-output, el reporte se guardará directamente en JSON sin el menú interactivo.
