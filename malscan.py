import hashlib
import os
import sys
import time
import base64
import json
import subprocess
from urllib.parse import quote
import requests
from virus_total_apis import PublicApi as VirusTotalPublicApi
from colorama import Fore, Back, Style, init

# Your VirusTotal API key
API_KEY_VT = '4e603c3a01a10515c1b1da28ccf061540958ed1b7932867e458774a4771c785b'
API_KEY_FS = 'zRsmCSFIW1fptPyA5LoMoTFrWNvh8PjeXT1o2NK'

# File Metadata
def file_metadata(file):
    print(Fore.CYAN + '\n>> Metadata')
    try:
        # Command to get metadata in JSON format
        command = ['exiftool', '-json', file]
        # Execute the command and get the output
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, text=True)
        # Parse the JSON output to get metadata
        metadata = json.loads(output)
        return metadata[0] if metadata else None
    except subprocess.CalledProcessError as e:
        return None

# Calculate the MD5 hash for a file
def calculate_md5(path):
    try:
        # Open the file in binary mode
        with open(path, 'rb') as file:
            # Read the file content in blocks of 4096 bytes
            md5 = hashlib.md5()
            while True:
                data = file.read(4096)
                if not data:
                    break
                md5.update(data)
            return md5.hexdigest()
    except FileNotFoundError:
        return None

def calculate_sha1(file):
    # Create an SHA-1 hash object
    sha1 = hashlib.sha1()
    # Read the file in blocks and update the hash object
    with open(file, 'rb') as file:
        while True:
            block = file.read(65536)  # Read 64KB at a time (you can adjust the block size)
            if not block:
                break
            sha1.update(block)

    # Get the SHA-1 hash in hexadecimal format
    hash_sha1 = sha1.hexdigest()
    return hash_sha1

def calculate_sha256sum(file):
    sha256sum = hashlib.sha256()
    with open(file, 'rb') as f:
        while True:
            # Read the file in blocks of 64KB
            data = f.read(65536)
            if not data:
                break
            sha256sum.update(data)
    return sha256sum.hexdigest()

# VirusTotal API: https://developers.virustotal.com/reference/overview
def analyze_vt(api_key, path, is_file):
    print(Fore.CYAN + '\n>> Analyzing with VirusTotal')
    if is_file:
        query = calculate_md5(path)
    else:
        query = path

    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    response = requests.get('https://www.virustotal.com/api/v3/search' + '?query=' + str(query), headers=headers)

    if response.status_code == 200:
        # Get analysis categories
        data = response.json()
        if data['data'] == []:
            print(Fore.YELLOW + '\tNo record of this file on VirusTotal, it is being uploaded now')
            # File size
            file_size_bytes = os.path.getsize(path)
            # Convert size to megabytes (1 MB = 1024*1024 bytes)
            file_size_mb = file_size_bytes / (1024 * 1024)
            # Set the limit to 32MB
            limit_mb = 32
            # Check if the file is under 32MB
            if file_size_mb < limit_mb:
                print(f"The file is {file_size_mb:.2f} MB and meets the {limit_mb} MB limit. It's being analyzed")
                # Need to upload the file for analysis
                url_upload = "https://www.virustotal.com/api/v3/files"
                files = {"file": (str(path), open(str(path), "rb"), "application/octet-stream")}
                headers = {
                    "accept": "application/json",
                    "x-apikey": api_key
                }
                # Upload the file to VirusTotal, if it's larger than 32MB, it needs to be done manually
                response = requests.post(url_upload, files=files, headers=headers)

                # Request to view analysis results
                time.sleep(1)
                headers = {
                    "accept": "application/json",
                    "x-apikey": api_key
                }
                response = requests.get('https://www.virustotal.com/api/v3/search' + '?query=' + str(query), headers=headers)
                data = response.json()
                data_id = data['data'][0]['id']
                if is_file:
                    print('\tYou can view the analysis at: ' + Fore.BLUE + 'https://www.virustotal.com/gui/file/' + data_id + '/details')
                else:
                    print('\tYou can view the analysis at: ' + Fore.BLUE + 'https://www.virustotal.com/gui/url/' + data_id + '/details')
            else:
                print(f"\tThe file is {file_size_mb:.2f} MB and exceeds the {limit_mb} MB limit.")
                print('\tYou need to manually upload the file to ' + Fore.BLUE + 'https://www.virustotal.com')

        else:
            analysis = data['data'][0]['attributes']['last_analysis_stats']
            reputation = data['data'][0]['attributes']['reputation']
            data_id = data['data'][0]['id']

            if is_file:
                print('\tYou can view the analysis at: ' + Fore.BLUE + 'https://www.virustotal.com/gui/file/' + data_id + '/details')
            else:
                print('\tYou can view the analysis at: ' + Fore.BLUE + 'https://www.virustotal.com/gui/url/' + data_id + '/details')

            # Check if at least one category is "malicious"
            if analysis['malicious'] > 0 or (reputation <= 0 and is_file):
                print(Fore.RED + "\tIt is not safe according to VirusTotal. Its CommunityScore is " + str(reputation))
            else:
                print(Fore.GREEN + "\tIt is safe according to VirusTotal. Its CommunityScore is " + str(reputation))
    else:
        print(Fore.YELLOW + "Error searching on VirusTotal")

# Analyzing with https://www.filescan.io
def analyze_fs(api_key, path, is_file):
    # Analyze reputation on filescan.io
    print(Fore.CYAN + '\n>> Analyzing with filescan.io')
    file_size_bytes = os.path.getsize(path)
    # Convert size to megabytes (1 MB = 1024*1024 bytes)
    file_size_mb = file_size_bytes / (1024 * 1024)
    # Set the limit to 32MB
    limit_mb = 32
    # Check if the file is under 32MB
    if is_file and file_size_mb < limit_mb:
        sha256 = calculate_sha256sum(path)

        headers_sha256 = {
            "accept": "application/json",
            "X-Api-Key": api_key
        }
        response =  requests.get('https://www.filescan.io/api/reputation/hash?sha256=' + str(sha256), headers=headers_sha256)

        if response.status_code == 200:
            data = response.json()
            verdict = data['overall_verdict']
            headers_info = {
                "accept": "application/json",
                "X-Api-Key": api_key
            }

            if verdict == 'unknown' or verdict == 'informational':
                # POST request
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
                    'rapid_mode': 'false',
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
                # File you want to send (replace 'hola' with the correct file path)
                files = {
                    'file': (str(path), open(str(path), 'rb')),
                }

                response_id_file =  requests.post('https://www.filescan.io/api/scan/file', headers=headers_id_file,
                                                data=data_id_file, files=files)
                if response_id_file.status_code == 200:
                    data_json = response_id_file.json()
                    id_file = data_json['flow_id']

                    headers_file = {
                        "accept": "application/json",
                        "X-Api-Key": api_key
                    }
                    response =  requests.get('https://www.filescan.io/api/scan/' + id_file + '/report?filter=general',
                                            headers=headers_file)
                    data = response.json()
                    if response.status_code == 200 and data != 'unknown':
                        while data['allAdditionalStepsDone'] == False or data['sourceArchive']['verdict'] == 'unknown':
                            time.sleep(10)
                            response =  requests.get(
                                'https://www.filescan.io/api/scan/' + id_file + '/report?filter=general',
                                headers=headers_file)
                            data = response.json()

                        id_report = ''
                        for report_id, report_data in data['reports'].items():
                            if id_report == '':
                                id_report = report_id
                                # Encode the string in Base64
                                encoded_string_bytes = base64.b64encode(id_report.encode('utf-8'))
                                # Convert the encoded bytes to a string
                                base64_string = encoded_string_bytes.decode('utf-8')
                                print('\tYou can see more information about the analysis at: ' + Fore.BLUE +
                                    'https://www.filescan.io/search-result?query=' + base64_string)
                                break

                        # Access the "verdict" result in each report
                        verdict = data['sourceArchive']['verdict']

                        if 'malicious' in verdict:
                            color = Fore.RED
                        else:
                            color = Fore.YELLOW
                        print('\tAccording to filescan.io, the file is ' + color + verdict)
                    else:
                        print('Empty response or not a 200 status code')
                else:
                    print('Error status code')
        
            else:
                id_report = data['filescan_reports'][0]['report_id']
                response_info =  requests.get(
                    'https://www.filescan.io/api/reports/' + id_report + '/chat-gpt', headers=headers_info)
                data_info = response_info.json()
                
                if data_info["detail"] != None:
                    # Encode the string in Base64
                    encoded_string_bytes = base64.b64encode(id_report.encode('utf-8'))
                    # Convert the encoded bytes to a string
                    base64_string = encoded_string_bytes.decode('utf-8')
                    print('\tYou can see more information about the analysis at: ' + Fore.BLUE +
                        'https://www.filescan.io/search-result?query=' + base64_string)
                if 'malicious' in verdict:
                    color = Fore.RED
                else:
                    color = Fore.YELLOW
                print('\tAccording to filescan.io, the file is ' + color + verdict)

        else:
            print('Something went wrong on filescan.io')

    # Para url
    elif str(path).startswith("http://") or str(path).startswith("https://"):
        url_encode = quote(path)
        headers_id = {
            "accept": "application/json",
            "X-Api-Key": api_key,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data_id = 'save_preset=false&url=' + url_encode + '&tags=&propagate_tags=true&password=&is_private=false&skip_whitelisted=false'
        response_id_url =  requests.post('https://www.filescan.io/api/scan/url', headers=headers_id, data=data_id)

        if response_id_url.status_code == 200:
            data_json = response_id_url.json()
            id_url = data_json['flow_id']
        else:
            print('Error status code')

        headers_report = {
            "accept": "application/json",
            "X-Api-Key": api_key
        }
        response =  requests.get('https://www.filescan.io/api/scan/' + id_url + '/report?filter=finalVerdict',
                                headers=headers_report)

        if response.status_code == 200:
            data = response.json()
            verdict_exists = True
            while verdict_exists:
                time.sleep(5)
                response =  requests.get('https://www.filescan.io/api/scan/' + id_url + '/report?filter=finalVerdict',
                                        headers=headers_report)
                data = response.json()
                for report_id, report_data in data['reports'].items():
                    # Access the "verdict" result in each report
                    if report_data['finalVerdict']['verdict'] != 'UNKNOWN':
                        verdict_exists = False

            for report_id, report_data in data['reports'].items():
                # Access the "verdict" result in each report
                verdict = report_data['finalVerdict']['verdict']
                id_report = report_id
                # Encode the string in Base64
                encoded_string_bytes = base64.b64encode(path.encode('utf-8'))
                # Convert the encoded bytes to a string
                base64_string = encoded_string_bytes.decode('utf-8')
                print('\tYou can see more information about the analysis at: ' + Fore.BLUE +
                      'https://www.filescan.io/search-result?query=' + base64_string)
                if 'malicious' in verdict:
                    color = Fore.RED
                    break
                else:
                    color = Fore.YELLOW
                print('\tAccording to filescan.io, the link is ' + color + verdict)
        else:
            print('Empty response or not a 200 status code')
    else:
        print(Fore.YELLOW + '\tCan not upload the file because of it size')
        print('\tYou need to manually upload the file to ' + Fore.BLUE + 'https://filescan.io')

if __name__ == "__main__":
    # Initialize colorama
    init(autoreset=True)

    is_file = True
    args = sys.argv[1]

    if not os.path.exists(args):
        if args:
            print('Analyzing URL: ' + Fore.MAGENTA + args)
            is_file = False
            analyze_vt(API_KEY_VT, args, is_file)
            analyze_fs(API_KEY_FS, args, is_file)

        else:
            print(Fore.YELLOW + "The parameter is incorrect.")
    else:
        print('Analyzing file: ' + Fore.MAGENTA + args + '\n')
        print('MD5: ' + calculate_md5(args))
        print('SHA1: ' + calculate_sha1(args))
        print('SHA256: ' + calculate_sha256sum(args))

        metadata = file_metadata(args)
        if metadata:
            for key, value in metadata.items():
                print(f"\t{key}: {value}")
        analyze_vt(API_KEY_VT, args, is_file)
        analyze_fs(API_KEY_FS, args, is_file)
