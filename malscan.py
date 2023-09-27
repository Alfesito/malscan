import hashlib
import os
import sys
import json
import requests
from virus_total_apis import PublicApi as VirusTotalPublicApi
from colorama import Fore, Back, Style, init

# Tu clave de API de VirusTotal
API_KEY_VT = '4e603c3a01a10515c1b1da28ccf061540958ed1b7932867e458774a4771c785b'
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

# VirusTotal api: https://developers.virustotal.com/reference/overview
def analizar_vt(API_KEY_VT, path, isfile):
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
        analysis = data['data'][0]['attributes']['last_analysis_stats']
        reputation = data['data'][0]['attributes']['reputation']           

        # Comprobar si al menos una categoría es "malicious"
        if analysis['malicious'] > 0 or (reputation <= 0 and isfile):
            print(Fore.RED + "\n[-] NO es seguro segun VirusTotal.")
        else:
            print(Fore.GREEN + "\n[+] Es seguro segun VirusTotal.")
    else:
        print(Fore.YELLOW + "\nError al buscar en VirusTotal.")

# Aanalizando con https://www.filescan.io
def analizar_fs(url):
    print('fs')

if __name__ == "__main__":
    # Inicializa colorama
    init(autoreset=True)

    argisfile = True
    args = sys.argv[1]

    if not os.path.exists(args):
        if args:
            argisfile = False
            analizar_vt(API_KEY_VT, args, argisfile)
            analizar_fs(args)
        else:
            print(Fore.YELLOW + "\nEl parámetro es incorrecto.")
    else:
        analizar_vt(API_KEY_VT, args, argisfile)
