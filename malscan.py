import argparse
import hashlib
import os
import json
import requests
from virus_total_apis import PublicApi as VirusTotalPublicApi
from colorama import Fore, Back, Style, init

# Tu clave de API de VirusTotal
API_KEY = 'your_api_key'
URL_SERCH_VT = 'https://www.virustotal.com/api/v3/search'

# Calcula el hash md5 para un archivo
def calcular_md5(file_path):
    try:
        # Abre el archivo en modo binario
        with open(file_path, 'rb') as archivo:
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

def analizar_archivo(api_key, file_path):

    hash = calcular_md5(file_path)
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    response = requests.get(URL_SERCH_VT+'?query='+str(hash), headers=headers)

    if response.status_code == 200:
        # Obtener las categorías de análisis
        data = response.json()
        analysis = data['data'][0]['attributes']['last_analysis_stats']
        reputation = data['data'][0]['attributes']['reputation']           

        # Comprobar si al menos una categoría es "malicious"
        if analysis['malicious'] > 0 or reputation < 1:
            print(Fore.RED + "\nNo es seguro instalar el ejecutable segun VirusTotal.")
        else:
            print("\nEl ejecutable es seguro segun VirusTotal.")
    else:
        print(Fore.GREEN + Fore.YELLOW + "\nError al buscar en VirusTotal.")

if __name__ == "__main__":
    # Inicializa colorama
    init(autoreset=True)
    parser = argparse.ArgumentParser(description="Analizar un archivo con VirusTotal")
    parser.add_argument("archivo", help="Ruta al archivo ejecutable a analizar")
    args = parser.parse_args()

    if not os.path.exists(args.archivo):
        print(Fore.YELLOW + "\nEl archivo "+args.archivo+" no existe.")
    else:
        analizar_archivo(API_KEY, args.archivo)
