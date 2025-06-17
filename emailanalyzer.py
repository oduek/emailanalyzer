# -*- coding: utf-8 -*-

"""
ANALIZADOR DE CORREOS ELECTRÓNICOS PARA DETECCIÓN DE PHISHING
-------------------------------------------------------------
Herramienta para análisis forense y de respuesta a incidentes.
Analiza encabezados, contenido, URLs y archivos adjuntos de un
archivo .eml para identificar indicadores de phishing.

Autor: Oduek
"""

import email
from email.header import decode_header
import re
import whois
import requests
from spellchecker import SpellChecker
from langdetect import detect, LangDetectException
from datetime import datetime
import os
import argparse
import hashlib
from bs4 import BeautifulSoup
import json
import xml.etree.ElementTree as ET # Import for XML generation

# Aqui se configura de la API Key de VirusTotal
# Ruta donde se guardará la API Key de VirusTotal de forma persistente
# Se guarda en el directorio home del usuario como un archivo oculto.
VT_API_KEY_FILE = os.path.join(os.path.expanduser("~"), ".phishing_analyzer_vt_key")

# Para la puntuación y calificacion de sospecha
# Asignare puntos a cada hallazgo para calcular un riesgo total.
SUSPICION_SCORES = {
    "HEADER_SPOOFING": 8,
    "AUTH_FAILURE": 9,
    "URL_REDIRECT": 5,
    "PUNYCODE_URL": 10,
    "RECENT_DOMAIN": 7,
    "URGENCY_KEYWORD": 6,
    "SPELLING_ERRORS": 5,
    "SYNTAX_FLAW": 3,
    "LINK_TEXT_MISMATCH": 8,
    "SUSPICIOUS_SENDER_TLD": 4,
    "DANGEROUS_ATTACHMENT": 15, # Puntuacion para los adjuntos
    "VIRUSTOTAL_MALICIOUS_DETECTION": 12, # Puntuacion para los resultados de virus total
    # Nuevas puntuaciones para reenvíos
    "FORWARDED_EMAIL_DETECTED": 1, # Indica que es un reenvío, base, no necesariamente malicioso
    "EMBEDDED_ORIGINAL_SPOOFING": 10, # Spoofing detectado en el *original* incrustado
    "EMBEDDED_ORIGINAL_URL_REDIRECT": 7, # Redirección URL en el *original* incrustado
    "EMBEDDED_ORIGINAL_PUNYCODE_URL": 12, # Punycode en el *original* incrustado
    "EMBEDDED_ORIGINAL_RECENT_DOMAIN": 8, # Dominio reciente en el *original* incrustado
    "EMBEDDED_ORIGINAL_URGENCY_KEYWORD": 8, # Palabra clave de urgencia en el *original* incrustado
    "EMBEDDED_ORIGINAL_SPELLING_ERRORS": 7, # Errores ortográficos en el *original* incrustado
    "EMBEDDED_ORIGINAL_LINK_TEXT_MISMATCH": 10, # URL ofuscada en *original* incrustado
}

# Para de Gestión de la API Key
def save_virustotal_api_key(api_key):
    """Guarda la API Key de VirusTotal en un archivo."""
    try:
        with open(VT_API_KEY_FILE, 'w') as f:
            f.write(api_key.strip())
        print(f"¡Tu API Key de VirusTotal ha sido guardada para futuros usos en {VT_API_KEY_FILE}!")
    except IOError as e:
        print(f"¡Oops! No pude guardar la API Key: {e}")

def load_virustotal_api_key():
    """Carga la API Key de VirusTotal desde un archivo."""
    if os.path.exists(VT_API_KEY_FILE):
        try:
            with open(VT_API_KEY_FILE, 'r') as f:
                return f.read().strip()
        except IOError as e:
            print(f"¡Oops! No pude cargar la API Key del archivo: {e}")
            return None
    return None

def delete_virustotal_api_key():
    """Elimina la API Key de VirusTotal del archivo."""
    if os.path.exists(VT_API_KEY_FILE):
        try:
            os.remove(VT_API_KEY_FILE)
            print("¡Tu API Key de VirusTotal ha sido eliminada con éxito!")
        except OSError as e:
            print(f"¡Oops! No pude eliminar la API Key: {e}")
    else:
        print("No hay ninguna API Key de VirusTotal guardada para eliminar.")

# Para el Análisis

def analyze_headers(msg_or_dict, is_embedded=False):
    """
    Analiza los encabezados del correo para obtener información forense
    y detectar señales de suplantación (spoofing).
    Puede recibir un objeto email.message o un diccionario con campos de encabezado.
    """
    forensic_data = {}
    suspicion_points = []
    prefix = "Original Message - " if is_embedded else ""

    if isinstance(msg_or_dict, dict): # Si es un diccionario (para el mensaje incrustado)
        subject = msg_or_dict.get("subject", "No disponible")
        from_addr = msg_or_dict.get("from", "No disponible")
        to_addr = msg_or_dict.get("to", "No disponible")
        date_val = msg_or_dict.get("date", "No disponible")
        message_id = "No disponible (incrustado)"
        authentication_results = "No disponible (incrustado)"
        return_path = None # No disponible para encabezados incrustados
        received_headers = [] # No disponible para encabezados incrustados
        source_ips = [] # No disponible para encabezados incrustados
    else: # Si es un objeto email.message
        subject = ''
        try:
            subject_header = decode_header(msg_or_dict["Subject"])[0]
            subject = subject_header[0].decode(subject_header[1] or 'utf-8') if isinstance(subject_header[0], bytes) else subject_header[0]
        except Exception:
            subject = "No se pudo decodificar el asunto"

        from_addr = msg_or_dict.get("From", "No disponible")
        to_addr = msg_or_dict.get("To", "No disponible")
        date_val = msg_or_dict.get("Date", "No disponible")
        message_id = msg_or_dict.get("Message-ID", "No disponible")
        authentication_results = msg_or_dict.get("Authentication-Results", "")
        return_path = msg_or_dict.get("Return-Path")
        received_headers = msg_or_dict.get_all("Received", [])
        source_ips = []
        for header in received_headers:
            # Extraer IPs (IPv4) de las cabeceras "Received"
            ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', header)
            # Filtrar IPs locales/privadas
            source_ips.extend([ip for ip in ips if not ip.startswith(('192.168.', '10.', '172.16.'))])
        source_ips = list(set(source_ips))


    # 1. Extraer información básica
    forensic_data['subject'] = subject
    forensic_data['from'] = from_addr
    forensic_data['to'] = to_addr
    forensic_data['date'] = date_val
    forensic_data['message_id'] = message_id
    if not is_embedded: # Estos solo aplican al correo externo
        forensic_data['mail_path'] = received_headers
        forensic_data['source_ips'] = source_ips
        forensic_data['authentication_results'] = authentication_results if authentication_results else "No disponible"

    # 2. Análisis de Suplantación (Spoofing)
    if return_path and from_addr and ('@' in return_path) and ('@' in from_addr):
        from_domain = from_addr.split('@')[-1].strip('>')
        return_path_domain = return_path.split('@')[-1].strip('>')
        if from_domain.lower() != return_path_domain.lower():
            suspicion_points.append({
                "type": f"{prefix}Suplantación de Remitente (Spoofing)",
                "reason": f"El dominio del remitente ('From': {from_domain}) no coincide con el de retorno ('Return-Path': {return_path_domain}).",
                "score": SUSPICION_SCORES["EMBEDDED_ORIGINAL_SPOOFING"] if is_embedded else SUSPICION_SCORES["HEADER_SPOOFING"]
            })
    # Para mensajes incrustados, podemos comparar el "From" incrustado con el "From" del correo que lo reenvió (no implementado en esta versión, sería una mejora futura)

    # 3. Verificar Autenticación (SPF, DKIM, DMARC) - Solo aplica al correo externo
    if not is_embedded:
        if "spf=fail" in authentication_results.lower() or "spf=softfail" in authentication_results.lower():
            suspicion_points.append({"type": "Fallo de Autenticación", "reason": "Fallo en validación SPF.", "score": SUSPICION_SCORES["AUTH_FAILURE"]})
        if "dkim=fail" in authentication_results.lower():
            suspicion_points.append({"type": "Fallo de Autenticación", "reason": "Fallo en validación DKIM.", "score": SUSPICION_SCORES["AUTH_FAILURE"]})
        if "dmarc=fail" in authentication_results.lower():
            suspicion_points.append({"type": "Fallo de Autenticación", "reason": "Fallo en política DMARC.", "score": SUSPICION_SCORES["AUTH_FAILURE"]})

    # 4. Remitente con dominio de nivel superior (TLD) extraño
    suspicious_tlds = ['.xyz', '.club', '.online', '.top', '.live', '.info', '.biz', '.icu']
    if '@' in from_addr:
        from_domain = from_addr.split('@')[-1].strip('>')
        if any(from_domain.endswith(tld) for tld in suspicious_tlds):
             suspicion_points.append({
                "type": f"{prefix}Remitente Extraño",
                "reason": f"El dominio del remitente utiliza un TLD poco común y a menudo es senal de abuso: '{from_domain}'.",
                "score": SUSPICION_SCORES["SUSPICIOUS_SENDER_TLD"] # Score es el mismo para embedded o no
            })

    return forensic_data, suspicion_points

def analyze_urls(body_plain, body_html, is_embedded=False):
    """
    Extrae, analiza y valida URLs del cuerpo del correo.
    """
    prefix = "Original Message - " if is_embedded else ""
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body_plain)
    url_analysis = []
    suspicion_points = []
    
    if body_html:
        soup = BeautifulSoup(body_html, 'html.parser')
        for a in soup.find_all('a', href=True):
            href = a['href']
            text = a.text.strip()
            if href.startswith('mailto:'): continue # Omit mailto links
            if href and href not in urls: # Add unique URLs found in HTML
                urls.append(href)
            if text and href and not (text.lower().strip() in href.lower().strip() or href.lower().strip() in text.lower().strip()):
                suspicion_points.append({
                    "type": f"{prefix}URL Ofuscada en Texto",
                    "reason": f"El texto '{text[:30]}...' apunta a una URL diferente: '{href[:50]}...'.",
                    "score": SUSPICION_SCORES["EMBEDDED_ORIGINAL_LINK_TEXT_MISMATCH"] if is_embedded else SUSPICION_SCORES["LINK_TEXT_MISMATCH"]
                })

    for url in set(urls):
        if url.startswith('mailto:'): continue
        analysis = {"url_original": url}
        try:
            response = requests.get(url, timeout=5, allow_redirects=True, headers={'User-Agent': 'Mozilla/5.0'})
            final_url = response.url
            analysis['url_final'] = final_url
            
            if url != final_url:
                suspicion_points.append({
                    "type": f"{prefix}URL Redirigida",
                    "reason": f"'{url[:30]}...' redirige a '{final_url[:50]}...'.",
                    "score": SUSPICION_SCORES["EMBEDDED_ORIGINAL_URL_REDIRECT"] if is_embedded else SUSPICION_SCORES["URL_REDIRECT"]
                })

            domain_match = re.search(r"https?://([^/]+)", final_url)
            if domain_match:
                domain = domain_match.group(1)
                analysis['dominio'] = domain
                
                if "xn--" in domain:
                    suspicion_points.append({
                        "type": f"{prefix}Punycode/IDN Homograph Attack",
                        "reason": f"Dominio con Punycode: '{domain}'.",
                        "score": SUSPICION_SCORES["EMBEDDED_ORIGINAL_PUNYCODE_URL"] if is_embedded else SUSPICION_SCORES["PUNYCODE_URL"]
                    })
                
                try:
                    domain_info = whois.whois(domain)
                    creation_date = domain_info.creation_date
                    if creation_date:
                        creation_date = creation_date[0] if isinstance(creation_date, list) else creation_date
                        age = (datetime.now() - creation_date).days
                        analysis['antiguedad_dominio_dias'] = age
                        if age < 90:
                            suspicion_points.append({
                                "type": f"{prefix}Dominio Reciente",
                                "reason": f"Dominio '{domain}' registrado hace solo {age} días.",
                                "score": SUSPICION_SCORES["EMBEDDED_ORIGINAL_RECENT_DOMAIN"] if is_embedded else SUSPICION_SCORES["RECENT_DOMAIN"]
                            })
                except Exception:
                     analysis['antiguedad_dominio_dias'] = 'No se pudo verificar'
            else:
                analysis['dominio'] = 'No se pudo extraer'

        except requests.exceptions.RequestException:
            analysis['error'] = "No se pudo acceder a la URL."
        
        url_analysis.append(analysis)
        
    return url_analysis, suspicion_points

def analyze_content(body, is_embedded=False):
    """
    Analiza el texto del correo en busca de urgencia y errores.
    """
    prefix = "Original Message - " if is_embedded else ""
    suspicion_points = []
    if not body: return suspicion_points

    try:
        lang = detect(body)
    except LangDetectException:
        lang = 'en'

    urgency_keywords = {
        'es': ['urgente', 'inmediato', 'verificar', 'cuenta suspendida', 'acción requerida', 'expira', 'última oportunidad', 'soporte técnico', 'premio', 'ganador', 'factura', 'reembolso', 'problema de seguridad','urgencia','pago','transferencia','expuesto','filtrado','filtración','importante','problema detectado','advertencia','bloqueo inminente','verificación necesaria','tiempo limitado','respuesta inmediata','pago pendiente','actualización obligatoria'],
        'en': ['urgent', 'immediate', 'verify', 'account suspended', 'action required', 'expires', 'last chance', 'technical support', 'prize', 'winner', 'invoice', 'refund', 'security issue','asap','fast','pay','exposed','transfer','leak','immediate action required','important notice','warning','security alert','verify now','limited time offer','payment overdue','update requiered','response needed','critical update','final reminder','unauthorized access detected']
    }
    lang_key = 'es' if 'es' in lang else 'en'
    for keyword in urgency_keywords[lang_key]:
        if re.search(r'\b' + re.escape(keyword) + r'\b', body, re.IGNORECASE):
            suspicion_points.append({
                "type": f"{prefix}Sentido de Urgencia",
                "reason": f"Palabra clave detectada: '{keyword}'.",
                "score": SUSPICION_SCORES["EMBEDDED_ORIGINAL_URGENCY_KEYWORD"] if is_embedded else SUSPICION_SCORES["URGENCY_KEYWORD"]
            })

    spell = SpellChecker(language=lang_key)
    words = re.findall(r'\b[a-zA-ZáéíóúÁÉÍÓÚñÑ]+\b', body.lower())
    misspelled = spell.unknown(words)
    if len(misspelled) > 5:
        suspicion_points.append({
            "type": f"{prefix}Errores Ortográficos",
            "reason": f"Se encontraron {len(misspelled)} posibles errores. Muestra: {list(misspelled)[:5]}.",
            "score": SUSPICION_SCORES["EMBEDDED_ORIGINAL_SPELLING_ERRORS"] if is_embedded else SUSPICION_SCORES["SPELLING_ERRORS"]
        })

    if len(body) > 100 and (sum(1 for c in body if c.isupper()) / len(body)) > 0.25:
         suspicion_points.append({"type": f"{prefix}Falla de Sintaxis", "reason": "Uso excesivo de mayúsculas (>25%).", "score": SUSPICION_SCORES["SYNTAX_FLAW"]})
         
    return suspicion_points

def query_virustotal(hash_value, api_key):
    """
    Consulta la API de VirusTotal para obtener el informe de un hash de archivo.
    Retorna un diccionario con los resultados relevantes o None si hay un error.
    """
    if not api_key:
        return None # No se puede consultar si no hay API key

    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status() # Generar un HTTPError para respuestas incorrectas (4xx o 5xx)
        data = response.json()

        if data and 'data' in data and 'attributes' in data['data']:
            attributes = data['data']['attributes']
            # Para la API v3, buscamos 'last_analysis_stats'
            if 'last_analysis_stats' in attributes:
                stats = attributes['last_analysis_stats']
                malicious_count = stats.get('malicious', 0)
                total_engines = stats.get('harmless', 0) + stats.get('malicious', 0) + stats.get('suspicious', 0) + stats.get('undetected', 0) + stats.get('timeout', 0)

                return {
                    "detected": malicious_count > 0,
                    "malicious_count": malicious_count,
                    "total_engines": total_engines,
                    "permalink": f"https://www.virustotal.com/gui/file/{hash_value}/detection"
                }
            elif 'error' in data:
                print(f"Error de VirusTotal para hash {hash_value[:10]}...: {data['error']['message']}")
                return {"error": data['error']['message']}
        
        return None # Si no se encuentra 'data' o 'attributes'

    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 401:
            print("Error de VirusTotal: API Key inválida o no autorizada. Revisa tu clave.")
            return {"error": "API Key inválida o no autorizada."}
        elif response.status_code == 404:
            # Hash no encontrado en VirusTotal
            return {"error": "Hash no encontrado en VirusTotal."}
        else:
            print(f"Error HTTP de VirusTotal: {http_err}")
            return {"error": f"Error HTTP: {http_err}"}
    except requests.exceptions.ConnectionError as conn_err:
        print(f"Error de conexión a VirusTotal: {conn_err}")
        return {"error": f"Error de conexión: {conn_err}"}
    except requests.exceptions.Timeout as timeout_err:
        print(f"Tiempo de espera agotado para VirusTotal: {timeout_err}")
        return {"error": f"Tiempo de espera agotado: {timeout_err}"}
    except requests.exceptions.RequestException as req_err:
        print(f"Error desconocido al consultar VirusTotal: {req_err}")
        return {"error": f"Error de solicitud: {req_err}"}
    except json.JSONDecodeError:
        print(f"Error al decodificar la respuesta JSON de VirusTotal para hash {hash_value[:10]}...")
        return {"error": "Respuesta JSON inválida."}
    except Exception as e:
        print(f"Ocurrió un error inesperado al procesar la respuesta de VirusTotal: {e}")
        return {"error": f"Error inesperado: {e}"}

def analyze_attachments(msg, virustotal_api_key=None, is_embedded=False):
    """
    Extrae y analiza archivos adjuntos en busca de tipos de archivo peligrosos
    y calcula sus hashes para análisis forense. Opcionalmente consulta VirusTotal.
    """
    prefix = "Original Message - " if is_embedded else ""
    attachment_forensics = []
    suspicion_points = []
    dangerous_extensions = [
        '.exe', '.pif', '.bat', '.scr', '.vbs', '.js', '.jar', '.msi', '.ps1', '.cmd','.vbs','.wsf','.hta','.lnk','.reg','.dll','.sys', # Extensiones peligrosas
        '.docm', '.xlsm', '.pptm', # Macros de Office
        '.zip', '.rar', '.iso', '.img', '.gz', '.7z', '.tar', '.bz2', '.tgz', '.arj', '.cab' # Archivos comprimidos o de imagen
    ]

    for part in msg.walk():
        if part.get_content_maintype() == 'multipart' or part.get('Content-Disposition') is None:
            continue
        
        # Si es un reenvío como 'message/rfc822' adjunto, se podría procesar recursivamente aquí
        if part.get_content_type() == 'message/rfc822':
            # print("  [INFO] Adjunto 'message/rfc822' detectado. Esto podría ser un correo reenviado como adjunto.")
            # Podríamos intentar parsear este sub-mensaje, pero esto añade complejidad.
            # Por ahora, lo registramos como un adjunto, pero no lo analizamos recursivamente aquí.
            pass

        filename = part.get_filename()
        if filename:
            payload = part.get_payload(decode=True)
            if not payload: continue
            
            md5_hash = hashlib.md5(payload).hexdigest()
            sha256_hash = hashlib.sha256(payload).hexdigest()

            forensic_info = {
                "filename": filename,
                "content_type": part.get_content_type(),
                "size_bytes": len(payload),
                "md5": md5_hash,
                "sha256": sha256_hash
            }
            
            # Verificar si la extensión es peligrosa
            ext = os.path.splitext(filename)[1].lower()
            if ext in dangerous_extensions:
                suspicion_points.append({
                    "type": f"{prefix}Adjunto Peligroso",
                    "reason": f"El archivo adjunto '{filename}' tiene una extensión de riesgo ('{ext}').",
                    "score": SUSPICION_SCORES["DANGEROUS_ATTACHMENT"]
                })
            
            # Consultar VirusTotal si hay API Key
            if virustotal_api_key:
                vt_results = query_virustotal(sha256_hash, virustotal_api_key)
                forensic_info['virustotal_results'] = vt_results
                if vt_results and vt_results.get('detected', False):
                    suspicion_points.append({
                        "type": f"{prefix}Detección de VirusTotal (Adjunto)",
                        "reason": f"VirusTotal detectó {vt_results['malicious_count']} motores maliciosos para el adjunto '{filename}'.",
                        "score": SUSPICION_SCORES["VIRUSTOTAL_MALICIOUS_DETECTION"]
                    })
            
            attachment_forensics.append(forensic_info)

    return attachment_forensics, suspicion_points

def get_email_bodies(msg):
    """Extrae el cuerpo del correo en texto plano y HTML."""
    body_plain = ""
    body_html = ""
    for part in msg.walk():
        ctype = part.get_content_type()
        cdispo = str(part.get('Content-Disposition'))
        # Solo procesar partes que no son adjuntos y no son multipart
        if 'attachment' not in cdispo and part.get_content_maintype() != 'multipart' and ctype != 'message/rfc822':
            charset = part.get_content_charset() or 'utf-8'
            payload = part.get_payload(decode=True)
            if not payload: continue
            try:
                if ctype == 'text/plain' and not body_plain:
                    body_plain = payload.decode(charset, errors='replace')
                elif ctype == 'text/html':
                    body_html = payload.decode(charset, errors='replace')
            except (UnicodeDecodeError, AttributeError):
                body_plain = payload.decode('latin1', errors='replace') # Fallback
    
    # Si solo hay HTML y no se extrajo texto plano, convertir HTML a texto plano
    if body_html and not body_plain:
        soup = BeautifulSoup(body_html, 'html.parser')
        body_plain = soup.get_text(separator=' ', strip=True)

    return body_plain, body_html

def get_file_hashes(file_path):
    """Calcula los hashes MD5 y SHA256 de un archivo."""
    hasher_md5 = hashlib.md5()
    hasher_sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        buf = f.read()
        hasher_md5.update(buf)
        hasher_sha256.update(buf)
    return hasher_md5.hexdigest(), hasher_sha256.hexdigest()

def is_forwarded_email(msg, subject):
    """
    Checks if the email is likely a forwarded message based on headers and subject.
    Returns (True, suspicion_points) if detected, (False, []) otherwise.
    """
    forward_indicators = []

    # 1. Check for "Fwd:" or similar in subject (case-insensitive, handles various forms)
    if re.search(r"^(Re:|Fwd:|RV:|FWD:)\s*(\[\d+\]:)?\s*", subject, re.IGNORECASE):
        forward_indicators.append({
            "type": "Asunto de Reenvío Detectado",
            "reason": f"El asunto '{subject[:50]}...' contiene un prefijo común de reenvío/respuesta.",
            "score": SUSPICION_SCORES["FORWARDED_EMAIL_DETECTED"]
        })
    
    # 2. Check for Resent-From/Resent-To headers
    if msg.get("Resent-From") or msg.get("Resent-To"):
        forward_indicators.append({
            "type": "Encabezados de Reenvío (Resent-*)",
            "reason": "Se detectaron encabezados 'Resent-From' o 'Resent-To', indicando un reenvío formal.",
            "score": SUSPICION_SCORES["FORWARDED_EMAIL_DETECTED"]
        })
    
    return bool(forward_indicators), forward_indicators

def extract_and_analyze_embedded_original(body_plain, body_html, virustotal_api_key=None):
    """
    Attempts to extract and analyze the original message embedded within a forwarded email's body.
    This function is best for pretty-printed forwarded emails, not message/rfc822 attachments.
    """
    embedded_original_data = {
        "headers": {},
        "urls": [],
        "attachments": [], # Attachments in embedded text are very hard to extract without full MIME
        "body_plain": "",
        "body_html": "",
        "is_detected": False
    }
    embedded_suspicions = []
    
    # --- Attempt to extract from plain text body ---
    # Common patterns for start of original message block
    original_message_start_keywords_regex = r"(^From: .*\s*Sent:.*\s*To:.*\s*Subject:)|(-+\s*Original Message\s*-+)|(---------- Forwarded message ---------)|(De: .*\s*Enviado el:.*\s*Para:.*\s*Asunto:)"
    
    match = re.search(original_message_start_keywords_regex, body_plain, re.IGNORECASE | re.DOTALL | re.MULTILINE)

    if match:
        embedded_original_data["is_detected"] = True
        
        # Try to parse key headers from the plain text block just before the actual body content starts
        # We take a reasonable chunk before the actual body content for header parsing
        header_block_start = match.start()
        header_block_end = match.end()
        pre_body_block = body_plain[header_block_start:header_block_end]
        
        # Extract common headers using regex
        embedded_from_match = re.search(r"From:\s*(.+)", pre_body_block, re.IGNORECASE)
        if embedded_from_match: embedded_original_data["headers"]["from"] = embedded_from_match.group(1).strip()
        
        embedded_subject_match = re.search(r"Subject:\s*(.+)", pre_body_block, re.IGNORECASE)
        if embedded_subject_match: embedded_original_data["headers"]["subject"] = embedded_subject_match.group(1).strip()
        
        embedded_to_match = re.search(r"To:\s*(.+)", pre_body_block, re.IGNORECASE)
        if embedded_to_match: embedded_original_data["headers"]["to"] = embedded_to_match.group(1).strip()
        
        embedded_date_match = re.search(r"Date:\s*(.+)", pre_body_block, re.IGNORECASE)
        if embedded_date_match: embedded_original_data["headers"]["date"] = embedded_date_match.group(1).strip()

        # The rest of the plain text body after the detected header block is assumed to be the original message body
        embedded_original_data["body_plain"] = body_plain[header_block_end:].strip()
        
        # --- Re-analyze embedded content for forensic data and suspicions ---
        # Analyze URLs in the embedded plain text body (and original HTML if available for more links)
        embedded_urls, embedded_url_suspicions = analyze_urls(embedded_original_data["body_plain"], body_html, is_embedded=True)
        embedded_original_data["urls"] = embedded_urls
        embedded_suspicions.extend(embedded_url_suspicions)

        # Analyze content in the embedded plain text body
        embedded_content_suspicions = analyze_content(embedded_original_data["body_plain"], is_embedded=True)
        embedded_suspicions.extend(embedded_content_suspicions)
        
        # Placeholder for embedded headers analysis.
        # We can't do full SPF/DKIM/DMARC as we only have parsed text, not raw headers.
        # But we can check for spoofing by comparing the extracted 'From' with typical legitimate forwarders
        # For example, if 'From' is from a bank, but the forwarding email is from Gmail.
        # (This specific check is more complex and left for future enhancements)

    # Return the extracted data and any new suspicions
    return embedded_original_data, embedded_suspicions

# This will be the main console printing function
def generate_console_report(report_data):
    """Generates the analysis report in console."""
    summary = report_data["analysis_summary"]
    print("\n" + "="*80)
    print("              REPORTE DE ANÁLISIS DE CORREO ELECTRÓNICO  ")
    print("="*80)
    print(f" Archivo Analizado: {summary['file_analyzed']}")
    print(f" Fecha de Análisis: {summary['analysis_date']}")
    print(f" Hash MD5 del Archivo EML: {summary['eml_file_md5']}")
    print(f" Hash SHA256 del Archivo EML: {summary['eml_file_sha256']}")
    
    if summary['virustotal_eml_results']:
        vt_eml = summary['virustotal_eml_results']
        if vt_eml.get('error'):
            print(f" Análisis VirusTotal (EML): ¡Hubo un problema! {vt_eml['error']}")
        elif vt_eml.get('detected'):
            print(f" Análisis VirusTotal (EML): ¡DETECTADO! {vt_eml['malicious_count']}/{vt_eml['total_engines']} motores lo marcan como malicioso. ({vt_eml['permalink']})")
        else:
            print(f" Análisis VirusTotal (EML): Limpio según {vt_eml['total_engines']} motores.")
    else:
        print(" Análisis VirusTotal (EML): No realizado (sin API Key o error).")

    print("\n" + "-"*30 + " RESUMEN EJECUTIVO " + "-"*30)
    print(f"\n NIVEL DE RIESGO: {summary['risk_level'].upper()}")
    print(f" PUNTAJE TOTAL DE SOSPECHA: {summary['total_suspicion_score']}")
    
    if summary['is_forwarded_email']:
        print("\n   ¡Este correo fue detectado como un MENSAJE REENVIADO!  ")
        if report_data["forensic_data"]["embedded_original_message"]["is_detected"]:
            print("   -> Se logró extraer y analizar parte del mensaje original incrustado.")
            original_headers_found = report_data["forensic_data"]["embedded_original_message"]["headers"]
            if original_headers_found:
                print(f"   Original From: {original_headers_found.get('from', 'N/A')}")
                print(f"   Original Subject: {original_headers_found.get('subject', 'N/A')}")
        else:
            print("   -> No se pudo extraer el mensaje original incrustado de forma clara para un análisis más profundo.")


    if not report_data["suspicion_indicators"]:
        print("\n   ¡Buenas noticias! No se encontraron indicadores de phishing claros en este correo.")
    else:
        print("\n   ¡ALERTA! SE DETECTARON INDICADORES DE PHISHING (ordenados por severidad):")
        for item in report_data["suspicion_indicators"]:
            print(f"   - [Puntaje: {item['score']:<2}] {item['type']:<28} | {item['reason']}")

    print("\n" + "-"*28 + " DATOS PARA ANÁLISIS FORENSE " + "-"*28)
    
    forensics = report_data["forensic_data"]
    print("\n1. Información Clave de Encabezados (Correo Reenviado - Externo):")
    for key, value in forensics["outer_email_headers"].items():
        if key not in ['mail_path', 'source_ips']: print(f"  - {key.replace('_', ' ').title():<25}: {value}")
    
    print("\n2. IPs de Origen Identificadas (Ruta del Correo Reenviado - Externo):")
    if forensics["outer_email_headers"].get('source_ips'):
        print(f"  - IPs: {', '.join(forensics['outer_email_headers']['source_ips'])}")
    else:
        print("  - No se extrajeron IPs públicas de la ruta de envío del correo reenviado.")

    print("\n3. Análisis de URLs Encontradas (Correo Reenviado - Externo):")
    if not forensics["outer_email_urls"]:
        print("  - No se encontraron URLs en el cuerpo del correo reenviado. ¡Bien!")
    else:
        for url_data in forensics["outer_email_urls"]:
            print(f"  - URL Original: {url_data['url_original']}")
            if 'error' in url_data: print(f"    - Error: ¡No se pudo acceder a la URL! {url_data['error']}")
            else:
                if url_data.get('url_final') != url_data.get('url_original'): print(f"    - Redirige a: {url_data['url_final']}")
                print(f"    - Dominio Final: {url_data['dominio']}")
                print(f"    - Antigüedad del Dominio: {url_data.get('antiguedad_dominio_dias', 'No se pudo verificar')} días")

    print("\n4. Análisis de Archivos Adjuntos (Correo Reenviado - Externo):")
    if not forensics["outer_email_attachments"]:
        print("  - ¡Fantástico! No se encontraron archivos adjuntos en este correo.")
    else:
        for att_data in forensics["outer_email_attachments"]:
            print(f"  - Archivo: {att_data['filename']} ({att_data['size_bytes']} bytes)")
            print(f"    - Tipo: {att_data['content_type']}")
            print(f"    - MD5: {att_data['md5']}")
            print(f"    - SHA256: {att_data['sha256']}")
            
            if 'virustotal_results' in att_data and att_data['virustotal_results']:
                vt_att = att_data['virustotal_results']
                if vt_att.get('error'):
                    print(f"    - VirusTotal: ¡Hubo un problema! {vt_att['error']}")
                elif vt_att.get('detected'):
                    print(f"    - VirusTotal: ¡DETECTADO! {vt_att['malicious_count']}/{vt_att['total_engines']} motores lo marcan como malicioso. (Enlace: {vt_att['permalink']})")
                else:
                    print(f"    - VirusTotal: Parece limpio según {vt_att['total_engines']} motores.")
            else:
                print("    - VirusTotal: Análisis no realizado (sin API Key o error anterior).")
            print("      (Consejo: Usa los hashes MD5/SHA256 para verificar manualmente en plataformas de seguridad).")

    # Sección para el mensaje original incrustado
    if forensics["embedded_original_message"] and forensics["embedded_original_message"]["is_detected"]:
        embedded_orig_data = forensics["embedded_original_message"]
        print("\n--- DATOS DEL MENSAJE ORIGINAL INCRUSTADO (Dentro del Reenvío) ---")
        print("\n1. Información Clave de Encabezados (Mensaje Original Incrustado):")
        if embedded_orig_data["headers"]:
            for key, value in embedded_orig_data["headers"].items():
                print(f"  - {key.replace('_', ' ').title():<25}: {value}")
        else:
            print("  - No se pudieron extraer encabezados claros del mensaje original incrustado.")

        print("\n2. Análisis de URLs Encontradas (Mensaje Original Incrustado):")
        if not embedded_orig_data["urls"]:
            print("  - No se encontraron URLs en el cuerpo del mensaje original incrustado.")
        else:
            for url_data in embedded_orig_data["urls"]:
                print(f"  - URL Original: {url_data['url_original']}")
                if 'error' in url_data: print(f"    - Error: ¡No se pudo acceder a la URL! {url_data['error']}")
                else:
                    if url_data.get('url_final') != url_data.get('url_original'): print(f"    - Redirige a: {url_data['url_final']}")
                    print(f"    - Dominio Final: {url_data['dominio']}")
                    print(f"    - Antigüedad del Dominio: {url_data.get('antiguedad_dominio_dias', 'No se pudo verificar')} días")
        
        print("\n3. Archivos Adjuntos (Mensaje Original Incrustado):")
        print("  - Nota: La extracción de archivos adjuntos de mensajes originales incrustados como texto/HTML es limitada y no se realiza directamente en esta versión.")
        
    print("\n" + "-"*27 + " EXPLICACIÓN DE LA PUNTUACIÓN " + "-"*27)
    print("""
 La puntuación total de sospecha se calcula sumando los puntos de cada indicador
 detectado. ¡Esta escala te ayuda a entender rápidamente el nivel de riesgo!

   -  Puntaje 0:         BAJO.  No se encontraron indicadores claros de phishing.
   -  Puntaje 1-10:      MEDIO. Contiene algunos elementos sospechosos. Ten precaución y
                         tal vez haz un análisis manual si algo no cuadra.
   -  Puntaje 11-20:     ALTO. ¡Alerta! Es muy probable que sea un intento de phishing.
                         Evita interactuar con el contenido a toda costa.
   -  Puntaje > 20:      CRÍTICO. ¡PELIGRO! Todos los indicadores apuntan a un ataque de
                         phishing confirmado. Trátalo como un incidente de seguridad grave.
""")

    print("\n" + "="*80)
    print("                   FIN DEL ANÁLISIS")
    print("                  ¡EStare disponible para proximos analisis!")
    print("="*80)

# This is the dedicated text report generator (similar to console but to file)
def generate_text_report(report_data, output_filepath):
    """Generates the analysis report in plain text and saves it to a file."""
    report_content = ""
    summary = report_data["analysis_summary"]
    
    report_content += "\n" + "="*80 + "\n"
    report_content += "              REPORTE DE ANÁLISIS DE CORREO ELECTRÓNICO  \n"
    report_content += "="*80 + "\n"
    report_content += f" Archivo Analizado: {summary['file_analyzed']}\n"
    report_content += f" Fecha de Análisis: {summary['analysis_date']}\n"
    report_content += f" Hash MD5 del Archivo EML: {summary['eml_file_md5']}\n"
    report_content += f" Hash SHA256 del Archivo EML: {summary['eml_file_sha256']}\n"
    
    if summary['virustotal_eml_results']:
        vt_eml = summary['virustotal_eml_results']
        if vt_eml.get('error'):
            report_content += f" Análisis VirusTotal (EML): ¡Hubo un problema! {vt_eml['error']}\n"
        elif vt_eml.get('detected'):
            report_content += f" Análisis VirusTotal (EML): ¡DETECTADO! {vt_eml['malicious_count']}/{vt_eml['total_engines']} motores lo marcan como malicioso. ({vt_eml['permalink']})\n"
        else:
            report_content += f" Análisis VirusTotal (EML): Limpio según {vt_eml['total_engines']} motores.\n"
    else:
        report_content += " Análisis VirusTotal (EML): No realizado (sin API Key o error).\n"

    report_content += "\n" + "-"*30 + " RESUMEN EJECUTIVO " + "-"*30 + "\n"
    report_content += f"\n NIVEL DE RIESGO: {summary['risk_level'].upper()}\n"
    report_content += f" PUNTAJE TOTAL DE SOSPECHA: {summary['total_suspicion_score']}\n"
    
    if summary['is_forwarded_email']:
        report_content += "\n   ¡Este correo fue detectado como un MENSAJE REENVIADO!  \n"
        if report_data["forensic_data"]["embedded_original_message"]["is_detected"]:
            report_content += "   -> Se logró extraer y analizar parte del mensaje original incrustado.\n"
            original_headers_found = report_data["forensic_data"]["embedded_original_message"]["headers"]
            if original_headers_found:
                report_content += f"   Original From: {original_headers_found.get('from', 'N/A')}\n"
                report_content += f"   Original Subject: {original_headers_found.get('subject', 'N/A')}\n"
        else:
            report_content += "   -> No se pudo extraer el mensaje original incrustado de forma clara para un análisis más profundo.\n"

    if not report_data["suspicion_indicators"]:
        report_content += "\n ✅ ¡Buenas noticias! No se encontraron indicadores de phishing claros en este correo.\n"
    else:
        report_content += "\n ❗ ¡ALERTA! SE DETECTARON INDICADORES DE PHISHING (ordenados por severidad):\n"
        for item in report_data["suspicion_indicators"]:
            report_content += f"   - [Puntaje: {item['score']:<2}] {item['type']:<28} | {item['reason']}\n"

    report_content += "\n" + "-"*28 + " DATOS PARA ANÁLISIS FORENSE " + "-"*28 + "\n"
    
    forensics = report_data["forensic_data"]
    report_content += "\n1. Información Clave de Encabezados (Correo Reenviado - Externo):\n"
    for key, value in forensics["outer_email_headers"].items():
        if key not in ['mail_path', 'source_ips']: report_content += f"  - {key.replace('_', ' ').title():<25}: {value}\n"
    
    report_content += "\n2. IPs de Origen Identificadas (Ruta del Correo Reenviado - Externo):\n"
    if forensics["outer_email_headers"].get('source_ips'):
        report_content += f"  - IPs: {', '.join(forensics['outer_email_headers']['source_ips'])}\n"
    else:
        report_content += "  - No se extrajeron IPs públicas de la ruta de envío del correo reenviado.\n"

    report_content += "\n3. Análisis de URLs Encontradas (Correo Reenviado - Externo):\n"
    if not forensics["outer_email_urls"]:
        report_content += "  - No se encontraron URLs en el cuerpo del correo reenviado. ¡Bien!\n"
    else:
        for url_data in forensics["outer_email_urls"]:
            report_content += f"  - URL Original: {url_data['url_original']}\n"
            if 'error' in url_data: report_content += f"    - Error: ¡No se pudo acceder a la URL! {url_data['error']}\n"
            else:
                if url_data.get('url_final') != url_data.get('url_original'): report_content += f"    - Redirige a: {url_data['url_final']}\n"
                report_content += f"    - Dominio Final: {url_data['dominio']}\n"
                report_content += f"    - Antigüedad del Dominio: {url_data.get('antiguedad_dominio_dias', 'No se pudo verificar')} días\n"

    report_content += "\n4. Análisis de Archivos Adjuntos (Correo Reenviado - Externo):\n"
    if not forensics["outer_email_attachments"]:
        report_content += "  - ¡Fantástico! No se encontraron archivos adjuntos en este correo.\n"
    else:
        for att_data in forensics["outer_email_attachments"]:
            report_content += f"  - Archivo: {att_data['filename']} ({att_data['size_bytes']} bytes)\n"
            report_content += f"    - Tipo: {att_data['content_type']}\n"
            report_content += f"    - MD5: {att_data['md5']}\n"
            report_content += f"    - SHA256: {att_data['sha256']}\n"
            
            if 'virustotal_results' in att_data and att_data['virustotal_results']:
                vt_att = att_data['virustotal_results']
                if vt_att.get('error'):
                    report_content += f"    - VirusTotal: ¡Hubo un problema! {vt_att['error']}\n"
                elif vt_att.get('detected'):
                    report_content += f"    - VirusTotal: ¡DETECTADO! {vt_att['malicious_count']}/{vt_att['total_engines']} motores lo marcan como malicioso. (Enlace: {vt_att['permalink']})\n"
                else:
                    report_content += f"    - VirusTotal: Parece limpio según {vt_att['total_engines']} motores.\n"
            else:
                report_content += "    - VirusTotal: Análisis no realizado (sin API Key o error anterior).\n"
            report_content += "      (Consejo: Usa los hashes MD5/SHA256 para verificar manualmente en plataformas de seguridad).)\n"

    if forensics["embedded_original_message"] and forensics["embedded_original_message"]["is_detected"]:
        embedded_orig_data = forensics["embedded_original_message"]
        report_content += "\n--- DATOS DEL MENSAJE ORIGINAL INCRUSTADO (Dentro del Reenvío) ---\n"
        report_content += "\n1. Información Clave de Encabezados (Mensaje Original Incrustado):\n"
        if embedded_orig_data["headers"]:
            for key, value in embedded_orig_data["headers"].items():
                report_content += f"  - {key.replace('_', ' ').title():<25}: {value}\n"
        else:
            report_content += "  - No se pudieron extraer encabezados claros del mensaje original incrustado.\n"

        report_content += "\n2. Análisis de URLs Encontradas (Mensaje Original Incrustado):\n"
        if not embedded_orig_data["urls"]:
            report_content += "  - No se encontraron URLs en el cuerpo del mensaje original incrustado.\n"
        else:
            for url_data in embedded_orig_data["urls"]:
                report_content += f"  - URL Original: {url_data['url_original']}\n"
                if 'error' in url_data: report_content += f"    - Error: ¡No se pudo acceder a la URL! {url_data['error']}\n"
                else:
                    if url_data.get('url_final') != url_data.get('url_original'): report_content += f"    - Redirige a: {url_data['url_final']}\n"
                    report_content += f"    - Dominio Final: {url_data['dominio']}\n"
                    report_content += f"    - Antigüedad del Dominio: {url_data.get('antiguedad_dominio_dias', 'No se pudo verificar')} días\n"
        
        report_content += "\n3. Archivos Adjuntos (Mensaje Original Incrustado):\n"
        report_content += "  - Nota: La extracción de archivos adjuntos de mensajes originales incrustados como texto/HTML es limitada y no se realiza directamente en esta versión.\n"
        
    report_content += "\n" + "-"*27 + " EXPLICACIÓN DE LA PUNTUACIÓN " + "-"*27 + "\n"
    report_content += """
 La puntuación total de sospecha se calcula sumando los puntos de cada indicador
 detectado. ¡Esta escala te ayuda a entender rápidamente el nivel de riesgo!

   -  Puntaje 0:         BAJO.  No se encontraron indicadores claros de phishing.
   -  Puntaje 1-10:      MEDIO. Contiene algunos elementos sospechosos. Ten precaución y
                         tal vez haz un análisis manual si algo no cuadra.
   -  Puntaje 11-20:     ALTO. ¡Alerta! Es muy probable que sea un intento de phishing.
                         Evita interactuar con el contenido a toda costa.
   -  Puntaje > 20:      CRÍTICO. ¡PELIGRO! Todos los indicadores apuntan a un ataque de
                         phishing confirmado. Trátalo como un incidente de seguridad grave.
""" + "\n"
    report_content += "\n" + "="*80 + "\n"
    report_content += "                   FIN DEL ANÁLISIS\n"
    report_content += "                  ¡EStare disponible para proximos analisis!\n"
    report_content += "="*80 + "\n"

    try:
        with open(output_filepath, 'w', encoding='utf-8') as f:
            f.write(report_content)
    except IOError as e:
        print(f"Error saving text report to {output_filepath}: {e}")

def generate_html_report(report_data, output_filepath):
    """Generates an HTML report from report_data and saves it to a file."""
    html_content = f"""
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Reporte de Análisis de Phishing - {report_data['analysis_summary']['file_analyzed']}</title>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 20px; background-color: #f4f4f4; }}
            .container {{ max-width: 900px; margin: auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
            h1, h2, h3 {{ color: #0056b3; }}
            .header-section {{ background-color: #e0f2f7; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
            .suspicion-section {{ border: 1px solid #ffcc00; background-color: #fffacd; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
            .forensic-section {{ border: 1px solid #ccc; background-color: #f9f9f9; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
            .risk-low {{ color: green; font-weight: bold; }}
            .risk-medium {{ color: orange; font-weight: bold; }}
            .risk-high {{ color: red; font-weight: bold; }}
            .risk-critical {{ color: darkred; font-weight: bold; }}
            ul {{ list-style-type: none; padding: 0; }}
            ul li {{ margin-bottom: 5px; }}
            .code-block {{ background-color: #eee; padding: 10px; border-radius: 5px; font-family: monospace; white-space: pre-wrap; word-break: break-all; }}
            .warning {{ color: darkorange; font-weight: bold; }}
            .error {{ color: darkred; font-weight: bold; }}
            footer {{ text-align: center; margin-top: 30px; font-size: 0.9em; color: #777; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1 style="text-align: center; color: #007bff;">  Reporte de Análisis de Correo Electrónico  </h1>
            <p style="text-align: center; font-style: italic;">Generado por el Analizador de Phishing de Oduek</p>

            <div class="header-section">
                <h2>Resumen del Análisis</h2>
                <ul>
                    <li><strong>Archivo Analizado:</strong> {report_data['analysis_summary']['file_analyzed']}</li>
                    <li><strong>Fecha de Análisis:</strong> {report_data['analysis_summary']['analysis_date']}</li>
                    <li><strong>Hash MD5 del Archivo EML:</strong> {report_data['analysis_summary']['eml_file_md5']}</li>
                    <li><strong>Hash SHA256 del Archivo EML:</strong> {report_data['analysis_summary']['eml_file_sha256']}</li>
    """

    # Add VirusTotal EML results
    vt_eml = report_data['analysis_summary'].get('virustotal_eml_results')
    if vt_eml:
        if vt_eml.get('error'):
            html_content += f"""<li><strong>Análisis VirusTotal (EML):</strong> <span class="warning">¡Hubo un problema! {vt_eml['error']}</span></li>"""
        elif vt_eml.get('detected'):
            html_content += f"""<li><strong>Análisis VirusTotal (EML):</strong> <span class="error">¡DETECTADO! {vt_eml['malicious_count']}/{vt_eml['total_engines']} motores lo marcan como malicioso.</span> (<a href="{vt_eml['permalink']}" target="_blank">Ver en VirusTotal</a>)</li>"""
        else:
            html_content += f"""<li><strong>Análisis VirusTotal (EML):</strong> Limpio según {vt_eml['total_engines']} motores.</li>"""
    else:
        html_content += """<li><strong>Análisis VirusTotal (EML):</strong> No realizado (sin API Key o error).</li>"""

    html_content += f"""
                    <li><strong>Nivel de Riesgo:</strong> <span class="risk-{report_data['analysis_summary']['risk_level'].lower().split(' ')[0]}">{report_data['analysis_summary']['risk_level'].upper()}</span></li>
                    <li><strong>Es un correo reenviado:</strong> {'Sí' if report_data['analysis_summary']['is_forwarded_email'] else 'No'}</li>
                </ul>
            </div>
    """

    # Suspicion Indicators
    if report_data["suspicion_indicators"]:
        html_content += """
            <div class="suspicion-section">
                <h2>❗ Indicadores de Phishing Detectados (por severidad)</h2>
                <ul>
        """
        for item in report_data["suspicion_indicators"]:
            html_content += f"""
                    <li><strong>[Puntaje: {item['score']}] {item['type']}:</strong> {item['reason']}</li>
            """
        html_content += """
                </ul>
            </div>
        """
    else:
        html_content += """
            <p style="color: green; font-weight: bold;">✅ ¡Buenas noticias! No se encontraron indicadores de phishing claros en este correo.</p>
        """

    # Forensic Data
    forensics = report_data["forensic_data"]
    html_content += """
            <div class="forensic-section">
                <h2>Datos para Análisis Forense</h2>

                <h3>1. Información Clave de Encabezados (Correo Externo)</h3>
                <ul>
        """
    for key, value in forensics["outer_email_headers"].items():
        if key not in ['mail_path', 'source_ips']:
            html_content += f"<li><strong>{key.replace('_', ' ').title()}:</strong> {value}</li>"
    html_content += f"""
                </ul>

                <h3>2. IPs de Origen Identificadas (Ruta del Correo Externo)</h3>
                <ul>
                    <li><strong>IPs:</strong> {', '.join(forensics['outer_email_headers'].get('source_ips', [])) if forensics['outer_email_headers'].get('source_ips') else 'No se extrajeron IPs públicas.'}</li>
                </ul>

                <h3>3. Análisis de URLs Encontradas (Correo Externo)</h3>
                <ul>
        """
    if forensics["outer_email_urls"]:
        for url_data in forensics["outer_email_urls"]:
            html_content += f"<li><strong>URL Original:</strong> {url_data['url_original']}<br>"
            if 'error' in url_data:
                html_content += f"    <span class='warning'>- Error: ¡No se pudo acceder a la URL! {url_data['error']}</span><br>"
            else:
                if url_data.get('url_final') != url_data.get('url_original'):
                    html_content += f"    - Redirige a: {url_data['url_final']}<br>"
                html_content += f"    - Dominio Final: {url_data['dominio']}<br>"
                html_content += f"    - Antigüedad del Dominio: {url_data.get('antiguedad_dominio_dias', 'No se pudo verificar')} días</li>"
    else:
        html_content += "<li>No se encontraron URLs en el cuerpo del correo externo.</li>"
    html_content += """
                </ul>

                <h3>4. Análisis de Archivos Adjuntos (Correo Externo)</h3>
                <ul>
        """
    if forensics["outer_email_attachments"]:
        for att_data in forensics["outer_email_attachments"]:
            html_content += f"""
                    <li><strong>Archivo:</strong> {att_data['filename']} ({att_data['size_bytes']} bytes)<br>
                        - Tipo: {att_data['content_type']}<br>
                        - MD5: {att_data['md5']}<br>
                        - SHA256: {att_data['sha256']}<br>
            """
            if 'virustotal_results' in att_data and att_data['virustotal_results']:
                vt_att = att_data['virustotal_results']
                if vt_att.get('error'):
                    html_content += f"        - VirusTotal: <span class='warning'>¡Hubo un problema! {vt_att['error']}</span><br>"
                elif vt_att.get('detected'):
                    html_content += f"        - VirusTotal: <span class='error'>¡DETECTADO! {vt_att['malicious_count']}/{vt_att['total_engines']} motores.</span> (<a href='{vt_att['permalink']}' target='_blank'>Ver en VirusTotal</a>)<br>"
                else:
                    html_content += f"        - VirusTotal: Parece limpio según {vt_att['total_engines']} motores.<br>"
            else:
                html_content += "        - VirusTotal: Análisis no realizado (sin API Key o error anterior).<br>"
            html_content += "      (Consejo: Usa los hashes MD5/SHA256 para verificar manualmente en plataformas de seguridad).</li>"
    else:
        html_content += "<li>No se encontraron archivos adjuntos en este correo externo.</li>"
    html_content += """
                </ul>
        """

    # Embedded Original Message Section
    if forensics["embedded_original_message"] and forensics["embedded_original_message"]["is_detected"]:
        embedded_orig_data = forensics["embedded_original_message"]
        html_content += """
                <hr>
                <h2>--- Datos del Mensaje Original Incrustado (Dentro del Reenvío) ---</h2>

                <h3>1. Información Clave de Encabezados (Mensaje Original Incrustado)</h3>
                <ul>
        """
        if embedded_orig_data["headers"]:
            for key, value in embedded_orig_data["headers"].items():
                html_content += f"<li><strong>{key.replace('_', ' ').title()}:</strong> {value}</li>"
        else:
            html_content += "<li>No se pudieron extraer encabezados claros del mensaje original incrustado.</li>"
        html_content += """
                </ul>

                <h3>2. Análisis de URLs Encontradas (Mensaje Original Incrustado)</h3>
                <ul>
        """
        if embedded_orig_data["urls"]:
            for url_data in embedded_orig_data["urls"]:
                html_content += f"<li><strong>URL Original:</strong> {url_data['url_original']}<br>"
                if 'error' in url_data:
                    html_content += f"    <span class='warning'>- Error: ¡No se pudo acceder a la URL! {url_data['error']}</span><br>"
                else:
                    if url_data.get('url_final') != url_data.get('url_original'):
                        html_content += f"    - Redirige a: {url_data['url_final']}<br>"
                    html_content += f"    - Dominio Final: {url_data['dominio']}<br>"
                    html_content += f"    - Antigüedad del Dominio: {url_data.get('antiguedad_dominio_dias', 'No se pudo verificar')} días</li>"
        else:
            html_content += "<li>No se encontraron URLs en el cuerpo del mensaje original incrustado.</li>"
        html_content += """
                </ul>
                <h3>3. Archivos Adjuntos (Mensaje Original Incrustado)</h3>
                <p>Nota: La extracción de archivos adjuntos de mensajes originales incrustados como texto/HTML es limitada y no se realiza directamente en esta versión.</p>
        """
    html_content += f"""
            </div>

            <div class="forensic-section">
                <h2>Explicación de la Puntuación</h2>
                <p>La puntuación total de sospecha se calcula sumando los puntos de cada indicador detectado. ¡Esta escala te ayuda a entender rápidamente el nivel de riesgo!</p>
                <ul>
                    <li><strong>Puntaje 0:</strong>         <span class="risk-low">BAJO.</span> No se encontraron indicadores claros de phishing.</li>
                    <li><strong>Puntaje 1-10:</strong>      <span class="risk-medium">MEDIO.</span> Contiene algunos elementos sospechosos. Ten precaución y tal vez haz un análisis manual si algo no te cuadra.</li>
                    <li><strong>Puntaje 11-20:</strong>     <span class="risk-high">ALTO.</span> ¡Alerta! Es muy probable que sea un intento de phishing. Evita interactuar con el contenido a toda costa.</li>
                    <li><strong>Puntaje > 20:</strong>      <span class="risk-critical">CRÍTICO.</span> ¡PELIGRO! Todos los indicadores apuntan a un ataque de phishing confirmado. Trátalo como un incidente de seguridad grave.</li>
                </ul>
            </div>

            <footer>
                <p>FIN DEL ANÁLISIS</p>
                <p>¡Estaré disponible para próximos análisis!</p>
                <p>Desarrollado por Oduek - <a href="https://github.com/oduek" target="_blank">https://github.com/oduek</a></p>
            </footer>
        </div>
    </body>
    </html>
    """
    try:
        with open(output_filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
    except IOError as e:
        print(f"Error saving HTML report to {output_filepath}: {e}")

def dict_to_xml(data, root_name="root"):
    """Recursively converts a dictionary to an XML Element."""
    root = ET.Element(root_name)
    _build_xml_from_dict(root, data)
    return root

def _build_xml_from_dict(parent, data):
    if isinstance(data, dict):
        for key, value in data.items():
            # Clean key for XML tag name (e.g., replace spaces, hyphens, non-alphanumeric except underscore)
            # Ensure the tag starts with a letter or underscore
            safe_key = re.sub(r'[^a-zA-Z0-9_]', '', key).replace(' ', '_')
            if not safe_key or not re.match(r'^[a-zA-Z_]', safe_key): # If key is empty or starts with non-letter/underscore
                safe_key = "_" + safe_key if safe_key else "item" # Prepend underscore or use 'item'
            child = ET.SubElement(parent, safe_key)
            _build_xml_from_dict(child, value)
    elif isinstance(data, list):
        for item in data:
            # For list items, create a generic tag, e.g., 'item' or 'entry'
            child = ET.SubElement(parent, "item")
            _build_xml_from_dict(child, item)
    else:
        parent.text = str(data)

def generate_xml_report(report_data, output_filepath):
    """Generates an XML report from report_data and saves it to a file."""
    try:
        # Define a top-level element name for the XML
        xml_root = dict_to_xml(report_data, "PhishingAnalysisReport")
        tree = ET.ElementTree(xml_root)
        
        # Use pretty_print for readability (requires Python 3.9+)
        try:
            ET.indent(tree, space="  ", level=0)
        except AttributeError:
            # Fallback for older Python versions if indent is not available
            pass 
        
        tree.write(output_filepath, encoding='utf-8', xml_declaration=True)
    except Exception as e:
        print(f"Error generando reporte XML: {e}")

# Función Principal y Generación de Reporte

def main():
    # ASCII Art Banner
    print(r"""
 ______             _ _          _   
|  ____|           (_) |        | |  
| |__  _ __ ___  __ _ _| |  __ _ _ __  __ _| |_ _ _______ _ __ 
|  __| | '_ ` _ \ / _` | | | / _` | '_ \ / _` | | | | |_  / _ \ '__|
| |____| | | | | | (_| | | || (_| | | | | (_| | | |_| |/ /  __/ |   
|______|_| |_| |_|\__,_|_|_| \__,_|_| |_|\__,_|_|\__, /___\___|_|   
                                                  __/ |             
                                                 |___/              
    """)
    print(" Desarrollado por Oduek ")
    print(" https://github.com/oduek ")
    print("")
    print("")
    print("¡Hola! Soy un asistente de análisis de phishing o SCAM en correos electrónicos con formato .eml.")
    print("Mi objetivo es ayudarte a identificar y comprender los riesgos asociados con correos sospechosos.")
    print("¡Vamos a revisar este correo electronico!\n")


    parser = argparse.ArgumentParser(
        description="Analizador de correos electrónicos (.eml) para detectar phishing.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Ejemplo de uso:
  python %(prog)s -f "correo_sospechoso.eml"
  python %(prog)s -f "correo.eml" --json-output reporte.json
  python %(prog)s -f "adjunto_malicioso.eml" --vt-api-key TU_API_KEY_VIRUSTOTAL
  python %(prog)s --vt-key-delete # Para eliminar la API Key de VirusTotal almacenada localmente en un archivo

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
"""
    )
    parser.add_argument("-f", "--file", type=str, help="Ruta al archivo .eml que se desea analizar.")
    parser.add_argument("--json-output", type=str, help="Ruta para guardar el reporte en formato JSON. Si no se especifica, el reporte se imprime en la consola.")
    parser.add_argument("--vt-api-key", type=str, default=None, help="Tu API Key de VirusTotal. Opcional. Si la provees aquí, se usará para esta ejecución y se guardará si no hay una existente.")
    parser.add_argument("--vt-key-delete", action="store_true", help="Elimina la API Key de VirusTotal guardada permanentemente y sale del script.")
    args = parser.parse_args()

    # --- Initial check for -f argument ---
    if not args.file and not args.vt_key_delete: # If no file and not just deleting key
        print("\n¡Atención! Es necesario especificar un archivo .eml para analizar. Usa la opción '-f' o '--file'.")
        parser.print_help()
        return

    # --- Manejo de la API Key de VirusTotal ---
    if args.vt_key_delete:
        delete_virustotal_api_key()
        return # Sale del script después de eliminar la clave

    virustotal_api_key = args.vt_api_key # Clave proporcionada por argumento

    if not virustotal_api_key: # Si no se proporcionó por argumento, intentar cargarla o pedirla
        loaded_key = load_virustotal_api_key()
        if loaded_key:
            use_loaded = input(f"¡He encontrado una API Key de VirusTotal guardada! ¿Quieres usarla? (s/n, o introduce una nueva): ").lower()
            if use_loaded == 's' or use_loaded == '':
                virustotal_api_key = loaded_key
                print("¡Usando la API Key guardada!")
            else:
                new_key = input("¡Entendido! Por favor, introduce la nueva API Key de VirusTotal: ")
                if new_key:
                    virustotal_api_key = new_key
                    save_virustotal_api_key(new_key)
                else:
                    print("No se proporcionó una nueva API Key. Continuaré sin el análisis de VirusTotal.")
        else: # No hay clave guardada y no se proporcionó por argumento
            use_vt = input("¿Te gustaría usar VirusTotal para un análisis más profundo de los archivos adjuntos? (s/n): ").lower()
            if use_vt == 's':
                vt_key = input("¡Genial! Por favor, introduce tu API Key de VirusTotal: ")
                if vt_key:
                    virustotal_api_key = vt_key
                    save_virustotal_api_key(vt_key)
                else:
                    print("No se proporcionó una API Key. Continuaré sin el análisis de VirusTotal.")
    elif virustotal_api_key and not load_virustotal_api_key():
        # Si se proporciona una clave por argumento y no hay una guardada, se guarda automáticamente
        save_virustotal_api_key(virustotal_api_key)


    # --- Continuar con el análisis del correo si se proporcionó un archivo ---
    if not os.path.exists(args.file):
        print(f"Error: El archivo '{args.file}' no fue encontrado. ¡Por favor, verifica la ruta!")
        return

  
    with open(args.file, 'rb') as f:
        msg = email.message_from_binary_file(f)
    
    eml_md5, eml_sha256 = get_file_hashes(args.file)

    body_plain, body_html = get_email_bodies(msg)
    
    # 1. Análisis del correo "externo" (el que fue reenviado)
    header_forensics_outer, header_suspicions_outer = analyze_headers(msg)
    content_suspicions_outer = analyze_content(body_plain)
    url_forensics_outer, url_suspicions_outer = analyze_urls(body_plain, body_html)
    attachment_forensics_outer, attachment_suspicions_outer = analyze_attachments(msg, virustotal_api_key)

    # 2. Detección de reenvío y análisis del mensaje "original" incrustado
    is_fwd, fwd_suspicions = is_forwarded_email(msg, header_forensics_outer.get('subject', ''))
    
    embedded_original_data = None
    embedded_original_suspicions = []
    
    if is_fwd:
        print("\n¡Alerta! Parece que este es un correo reenviado. Intentando analizar el mensaje original incrustado...")
        embedded_original_data, embedded_original_suspicions = extract_and_analyze_embedded_original(body_plain, body_html, virustotal_api_key)
        
        if embedded_original_data and embedded_original_data["is_detected"]:
            # Realizar análisis de encabezados del mensaje original si se pudo extraer información clave
            # Note: No podemos hacer análisis SPF/DKIM/DMARC para el mensaje incrustado directamente aquí
            # Solo podemos analizar el 'From' y 'Subject' extraídos
            embedded_header_forensics, embedded_header_suspicions = analyze_headers(embedded_original_data["headers"], is_embedded=True)
            embedded_original_suspicions.extend(embedded_header_suspicions)
            
        else:
            print("No se pudo extraer o analizar el mensaje original incrustado de forma clara.")

    # Opcional: Análisis del hash del EML completo con VirusTotal
    eml_vt_results = None
    if virustotal_api_key:
        print(f"\nConsultando VirusTotal para el hash SHA256 del archivo EML ({eml_sha256[:10]}...).")
        eml_vt_results = query_virustotal(eml_sha256, virustotal_api_key)
        if eml_vt_results and eml_vt_results.get('detected', False):
            header_suspicions_outer.append({
                "type": "Detección de VirusTotal (EML General)",
                "reason": f"VirusTotal detectó {eml_vt_results['malicious_count']} motores maliciosos para el archivo EML completo.",
                "score": SUSPICION_SCORES["VIRUSTOTAL_MALICIOUS_DETECTION"]
            })
        elif eml_vt_results and "error" in eml_vt_results:
            print(f"No se pudo consultar VirusTotal para el EML general: {eml_vt_results['error']}")
    
    # Consolidar todos los puntos de sospecha
    all_suspicions = (
        header_suspicions_outer + 
        content_suspicions_outer + 
        url_suspicions_outer + 
        attachment_suspicions_outer + 
        fwd_suspicions + # Sospechas de que es un reenvío
        embedded_original_suspicions # Sospechas del mensaje original incrustado
    )
    all_suspicions = sorted(all_suspicions, key=lambda x: x['score'], reverse=True)
    total_score = sum(item['score'] for item in all_suspicions)
    
    risk_level = "Bajo"
    if 1 <= total_score <= 10: risk_level = "Medio. Se recomienda precaución."
    elif 11 <= total_score <= 20: risk_level = "Alto. Es muy probable que sea phishing."
    elif total_score > 20: risk_level = "Crítico. Phishing casi confirmado."

    # --- Estructurar datos para reporte ---
    report_data = {
        "analysis_summary": {
            "file_analyzed": os.path.basename(args.file),
            "analysis_date": datetime.now().isoformat(),
            "eml_file_md5": eml_md5,
            "eml_file_sha256": eml_sha256,
            "virustotal_eml_results": eml_vt_results,
            "is_forwarded_email": is_fwd,
            "risk_level": risk_level,
            "total_suspicion_score": total_score
        },
        "suspicion_indicators": all_suspicions,
        "forensic_data": {
            "outer_email_headers": header_forensics_outer,
            "outer_email_urls": url_forensics_outer,
            "outer_email_attachments": attachment_forensics_outer,
            "embedded_original_message": embedded_original_data # Incluir datos del original incrustado
        }
    }

    # --- Output Format Selection ---
    print("\n")
    print("¿Cómo te gustaría exportar los resultados del análisis?")
    print("1: Imprimir en consola (por defecto)")
    print("2: Guardar como Archivo de Texto (.txt)")
    print("3: Guardar como Archivo HTML (.html)")
    print("4: Guardar como Archivo XML (.xml)")
    print("5: Guardar como Archivo JSON (.json)")
    print("6: Guardar en TODOS los formatos (txt, html, xml, json)")
    
    export_choice = input("Elige una opción (1-6, o Enter para 1): ").strip() or '1'

    # Determine output directory and base filename for export
    # Create 'reportes' subdirectory
    base_output_dir = os.path.dirname(args.file) if os.path.dirname(args.file) else os.getcwd()
    reports_folder = os.path.join(base_output_dir, "reportes")

    if not os.path.exists(reports_folder):
        try:
            os.makedirs(reports_folder, exist_ok=True) # exist_ok=True prevents error if directory already exists
            print(f"¡Carpeta 'reportes' creada en: {reports_folder}!")
        except OSError as e:
            print(f"Error: No se pudo crear la carpeta 'reportes' en '{reports_folder}': {e}. Los reportes se guardarán en el directorio actual del archivo EML.")
            reports_folder = base_output_dir # Fallback to base directory if 'reportes' cannot be created

    output_base_filename_for_export = os.path.splitext(os.path.basename(args.file))[0] + "_report"
    timestamp_for_filename = datetime.now().strftime('%Y%m%d_%H%M%S')

    if export_choice == '1':
        generate_console_report(report_data)
    elif export_choice in ['2', '3', '4', '5', '6']:
        # Ensure reports_folder is valid before proceeding with file saves
        if not os.path.exists(reports_folder):
            print("No se pudo acceder o crear el directorio de reportes. El reporte no se guardará en archivo.")
            generate_console_report(report_data) # Fallback to console
            return

        if export_choice == '2' or export_choice == '6':
            output_filepath_txt = os.path.join(reports_folder, f"{output_base_filename_for_export}_{timestamp_for_filename}.txt")
            generate_text_report(report_data, output_filepath_txt)
            print(f"¡Reporte de texto guardado en: {output_filepath_txt}!")
        
        if export_choice == '3' or export_choice == '6':
            output_filepath_html = os.path.join(reports_folder, f"{output_base_filename_for_export}_{timestamp_for_filename}.html")
            generate_html_report(report_data, output_filepath_html)
            print(f"¡Reporte HTML guardado en: {output_filepath_html}!")
        
        if export_choice == '4' or export_choice == '6':
            output_filepath_xml = os.path.join(reports_folder, f"{output_base_filename_for_export}_{timestamp_for_filename}.xml")
            generate_xml_report(report_data, output_filepath_xml)
            print(f"¡Reporte XML guardado en: {output_filepath_xml}!")
        
        if export_choice == '5' or export_choice == '6':
            # This handles the case where --json-output was provided directly as an argument,
            # or if JSON is chosen interactively.
            # If args.json_output is set, prioritize that path for JSON.
            # Otherwise, use the dynamically generated path inside reports_folder.
            final_json_output_path = args.json_output if args.json_output else os.path.join(reports_folder, f"{output_base_filename_for_export}_{timestamp_for_filename}.json")
            with open(final_json_output_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=4, ensure_ascii=False)
            print(f"¡Reporte JSON guardado con éxito en: {final_json_output_path}!")
    else:
        print("Opción de exportación inválida. No se generará ningún archivo de reporte adicional.")
        generate_console_report(report_data) # Fallback to console report

if __name__ == "__main__":
    main()
