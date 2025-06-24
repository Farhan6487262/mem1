import os
import subprocess
import urllib.request
import sys
import json

WINPMEM_EXE = "winpmem.exe"
OUTPUT_DMP = "memory_dump.dmp"

def download_winpmem():
    if os.path.exists(WINPMEM_EXE):
        print("[*] winpmem.exe already exists.")
        return

    print("[*] Fetching latest WinPmem release info from GitHub...")
    try:
        with urllib.request.urlopen("https://api.github.com/repos/Velocidex/WinPmem/releases/latest") as url:
            data = json.loads(url.read().decode())
            assets = data.get("assets", [])
            print(f"[*] Found {len(assets)} assets in the latest release:")
            for asset in assets:
                print(f"    - {asset['name']}")

            for asset in assets:
                if "winpmem" in asset["name"].lower() and asset["name"].endswith(".exe"):
                    download_url = asset["browser_download_url"]
                    break
            else:
                raise Exception("Suitable WinPmem asset not found.")

        print(f"[*] Downloading: {download_url}")
        urllib.request.urlretrieve(download_url, WINPMEM_EXE)
        print("[+] WinPmem downloaded.")
    except Exception as e:
        print("[-] Failed to auto-download WinPmem.")
        print("    Please manually download from: https://github.com/Velocidex/WinPmem/releases")
        raise e

def create_memory_dump():
    if os.name != 'nt':
        raise EnvironmentError("This script is only supported on Windows.")

    # You can enhance this check if you want to confirm admin privileges here
    
    download_winpmem()
    print("[*] Creating memory dump(s)... (requires Administrator privileges)")
    try:
        subprocess.run([WINPMEM_EXE, "acquire", OUTPUT_DMP], check=True)
        print(f"[+] .dmp memory dump created: {os.path.abspath(OUTPUT_DMP)}")
        return os.path.abspath(OUTPUT_DMP)
    except subprocess.CalledProcessError as e:
        print("[-] Failed to create memory dump(s):", e)
        raise e
