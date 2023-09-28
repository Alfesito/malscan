import hashlib
import os
import sys
import json
import time
from urllib.parse import quote
import requests
from virus_total_apis import PublicApi as VirusTotalPublicApi
from colorama import Fore, Back, Style, init

# Tu clave de API de VirusTotal
API_KEY_VT = 'api_key'
API_KEY_FS = 'api_key'
URL_SERCH_VT = 'https://www.virustotal.com/api/v3/search'

# Calcula el hash md5 para un archivo
def calcular_md5(path):
    try:
        # Abre el archivo en modo binario
        with open(path, 'rb') as archivo:
            # Lee el contenido del archivo en bloques de 4096 bytes
            md5 = hashlib.md5()
            while True:
                data = archivo.read(4096)
                if not data:
                    break
                md5.update(data)
            return md5.hexdigest()
    except FileNotFoundError:
        return None

def calcular_sha256sum(archivo):
    sha256sum = hashlib.sha256()
    with open(archivo, 'rb') as f:
        while True:
            # Lee el archivo en bloques de 64KB
            data = f.read(65536)
            if not data:
                break
            sha256sum.update(data)
    return sha256sum.hexdigest()

# VirusTotal api: https://developers.virustotal.com/reference/overview
def analizar_vt(API_KEY_VT, path, isfile):
    print(Fore.CYAN +'\n>> Analizando con VirusTotal')
    if argisfile:
        query = calcular_md5(path)
    else:
        query = path

    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY_VT
    }
    response = requests.get(URL_SERCH_VT+'?query='+str(query), headers=headers)

    if response.status_code == 200:
        # Obtener las categorías de análisis
        data = response.json()
        if data['data'] == []:
            print(Fore.YELLOW + 'No hay registro de este archivo en VirusTotal')
        else:
            analysis = data['data'][0]['attributes']['last_analysis_stats']
            reputation = data['data'][0]['attributes']['reputation']           

            # Comprobar si al menos una categoría es "malicious"
            if analysis['malicious'] > 0 or (reputation <= 0 and isfile):
                print(Fore.RED + "[-] NO es seguro segun VirusTotal.")
            else:
                print(Fore.GREEN + "[+] Es seguro segun VirusTotal.")
    else:
        print(Fore.YELLOW + "Error al buscar en VirusTotal.")

# Analizando con https://www.filescan.io
def analizar_fs(api_key, path, isfile):
    print(Fore.CYAN + '\n>> Analizando con filescan.io')
    # Analizamos la reputación en filescan.io
    if isfile:
        sha256 = calcular_sha256sum(path)

        headers_sha256 = {
            "accept": "application/json",
            "X-Api-Key": api_key
        }
        response = requests.get('https://www.filescan.io/api/reputation/hash?sha256='+str(sha256), headers=headers_sha256)

        if response.status_code == 200:
            data = response.json()
            verdict = data['overall_verdict']
            if verdict == 'unknown' or verdict == 'informational':
                # POST req
                headers_id_file = {
                    "accept": "application/json",
                    "X-Api-Key": api_key,
                }
                data_id_file = {
                    'save_preset': 'true',
                    'visualization': 'true',
                    'extracted_files_osint': 'true',
                    'extended_osint': 'true',
                    'input_file_yara': 'true',
                    'skip_whitelisted': 'true',
                    'rapid_mode': 'true',
                    'whois': 'true',
                    'osint': 'true',
                    'is_private': 'true',
                    'propagate_tags': 'true',
                    'files_download': 'true',
                    'images_ocr': 'true',
                    'ips_meta': 'true',
                    'tags': '',
                    'password': '',
                    'resolve_domains': 'true',
                    'description': '',
                    'extracted_files_yara': 'true',
                }
                # Archivo que deseas enviar (reemplaza 'hola' con la ruta correcta al archivo)
                files= {
                    'file': ('hola', open('hola', 'rb')),
                }       

                response_id_file = requests.post('https://www.filescan.io/api/scan/file', headers=headers_id_file, data=data_id_file, files=files)
                if response_id_file.status_code == 200:
                    data_json = response_id_file.json()
                    id_file = data_json['flow_id']

                    headers_file = {
                    "accept": "application/json",
                    "X-Api-Key": api_key
                    }
                    response = requests.get('https://www.filescan.io/api/scan/' + id_file + '/report?filter=general', headers=headers_file)
                    data = response.json()
                    if response.status_code == 200:
                        while data['allAdditionalStepsDone'] == False or data['sourceArchive']['verdict'] == 'unknown':
                            time.sleep(10)
                            response = requests.get('https://www.filescan.io/api/scan/' + id_file + '/report?filter=general', headers=headers_file)
                            data = response.json()
                        # Accede al resultado de "verdict" en cada informe
                        verdict = data['sourceArchive']['verdict']
                        
                        if 'malicious' in verdict:
                            color = Fore.RED
                        else:                
                            color = Fore.YELLOW
                        print('Según filescan.io el archivo es ' + color + verdict)
                    else:
                        print('Respuesta vacía o no es un código de estado 200')
                else:
                    print('Error status code')
            else:
                if 'malicious' in verdict:
                    color = Fore.RED
                else:
                    color = Fore.YELLOW
                print('Según filescan.io el archivo es ' + color + verdict)
        else:
            print('Algo ha ido mal en filescan.io')
    elif str(path).startswith("http://") or str(path).startswith("https://"):
        url_encode = quote(path)
        headers_id = {
            "accept": "application/json",
            "X-Api-Key": api_key,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data_id = 'save_preset=false&url=' + url_encode + '&tags=&propagate_tags=true&password=&is_private=false&skip_whitelisted=false'
        response_id_url = requests.post('https://www.filescan.io/api/scan/url', headers=headers_id, data=data_id)

        if response_id_url.status_code == 200:  
            data_json = response_id_url.json()
            id_url = data_json['flow_id']
        else:
            print('Error status code')

        headers_report = {
            "accept": "application/json",
            "X-Api-Key": api_key
        }
        response = requests.get('https://www.filescan.io/api/scan/' + id_url + '/report?filter=finalVerdict', headers=headers_report)

        if response.status_code == 200:
            data = response.json()
            bolVerdict = True
            while  bolVerdict:
                time.sleep(5)
                response = requests.get('https://www.filescan.io/api/scan/' + id_url + '/report?filter=finalVerdict', headers=headers_report)
                data = response.json()
                for report_id, report_data in data['reports'].items():
                    # Accede al resultado de "verdict" en cada informe
                    if report_data['finalVerdict']['verdict'] != 'UNKNOWN': 
                        bolVerdict = False
        
            for report_id, report_data in data['reports'].items():
                # Accede al resultado de "verdict" en cada informe
                verdict = report_data['finalVerdict']['verdict']

                if 'malicious' in verdict:
                    color = Fore.RED
                    break
                else:                
                    color = Fore.YELLOW
                print('Según filescan.io el enlace es ' + color + verdict)
        else:
            print('Respuesta vacía o no es un código de estado 200')


if __name__ == "__main__":
    # Inicializa colorama
    init(autoreset=True)

    argisfile = True
    args = sys.argv[1]

    if not os.path.exists(args):
        if args:
            print('Analisis de la url: ' + Fore.MAGENTA + args + '\n')
            argisfile = False
            analizar_vt(API_KEY_VT, args, argisfile)
            analizar_fs(API_KEY_FS, args, argisfile)

        else:
            print(Fore.YELLOW + "El parámetro es incorrecto.")
    else:
        print('Analisis del achivo: ' + Fore.MAGENTA + args + '\n')
        print('MD5: ' + calcular_md5(args))
        print('SHA256: ' + calcular_sha256sum(args))
        analizar_vt(API_KEY_VT, args, argisfile)
        analizar_fs(API_KEY_FS, args, argisfile)