# Malscan a Malware Analysis Tool
This Python script is designed to perform antivirus analysis on files and URLs using VirusTotal and FileScan.io APIs. It calculates various file hashes (MD5, SHA-1, SHA-256) and retrieves metadata using ExifTool for files. The analysis results are displayed in the console, including information on the file's safety status.

## Prerequisites
Before running this script, you need to obtain API keys for both VirusTotal and FileScan.io. You can obtain these keys by signing up for developer accounts on their respective websites.

Make sure you have the following libraries installed:
- hashlib: Used for calculating file hashes (MD5, SHA-1, SHA-256).
- os: Provides functions for interacting with the operating system, such as checking file existence.
- time: Used for adding delays during API requests.
- base64: Used for encoding and decoding data to/from Base64.
- json: Used for parsing JSON responses from APIs.
- subprocess: Allows running external commands, used for metadata retrieval with ExifTool.
- urllib.parse: Used for URL encoding.
- requests: Used for making HTTP requests to VirusTotal and FileScan.io.
- virus_total_apis: A Python library for interacting with the VirusTotal API.
- colorama: Used for console text color formatting.

## Configuration
You need to configure the following variables in the script:
- API_KEY_VT: Your VirusTotal API key.
- API_KEY_FS: Your FileScan.io API key.

## Usage
To analyze a file, run the script with the file's path as an argument:

```shell
python malscan.py /path/to/your/file
```
To analyze a URL, provide the URL as an argument:

```shell
python malscan.py https://example.com
```

## Output
The script provides detailed analysis results for the file or URL, including the following information:
- Metadata (if available).
- MD5 hash.
- SHA-1 hash.
- SHA-256 hash.
- Analysis results from VirusTotal:
	- VirusTotal URL for more details.
	- Safety status based on precess and community score.
- Analysis results from FileScan.io (for files only):
	- FileScan.io URL for more details.
	- Safety status based on the verdict.

## Additional Notes
- The script supports both local files and URLs.
- If a file is not found, a warning will be displayed.
- If a file exceeds 32MB, you will need to manually upload it to VirusTotal and FileScan.io for analysis.
- FileScan.io is used primarily for file analysis, while VirusTotal is used for both file and URL analysis.
- The script includes additional delays to allow for API processing.

## Disclaimer
This script is provided for educational and informational purposes. Be aware of API usage limitations, terms of service, and compliance with applicable laws and regulations when using these services.
