#!/usr/bin/env python3

import os
import argparse
import magic
import hashlib
import json
import csv
import requests
from colorama import Fore, Style, init

# Init colorama
init(autoreset=True)

# ------------------ Configuration ------------------ #
SIGNATURES = {
    'JPEG image data': ['.jpg', '.jpeg'],
    'PNG image data': ['.png'],
    'PDF document': ['.pdf'],
    'Microsoft Word': ['.doc', '.docx'],
    'Microsoft Excel': ['.xls', '.xlsx'],
    'Microsoft PowerPoint': ['.ppt', '.pptx'],
    'Zip archive data': ['.zip', '.docx', '.xlsx', '.pptx'],
    'RAR archive data': ['.rar'],
    '7-zip archive data': ['.7z'],
    'ASCII text': ['.txt', '.log', '.csv'],
    'HTML document': ['.html', '.htm'],
    'Windows executable': ['.exe'],
    'ELF': ['.elf'],
    'MP4': ['.mp4'],
    'ISO 9660 CD-ROM': ['.iso'],
}

def get_true_type(file_path):
    try:
        return magic.from_file(file_path)
    except:
        return "Unreadable"

def hash_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except:
        return None

def vt_lookup(hash_val, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{hash_val}"
    headers = {"x-apikey": api_key}
    try:
        res = requests.get(url, headers=headers)
        if res.status_code == 200:
            data = res.json()
            return data['data']['attributes']['last_analysis_stats']
        elif res.status_code == 404:
            return {"undetected": True}
        else:
            return {"error": f"VT Error: {res.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def check_signature(file_path, api_key=None):
    sig = get_true_type(file_path)
    _, ext = os.path.splitext(file_path)
    ext = ext.lower()
    result = {
        "file": file_path,
        "extension": ext,
        "signature": sig,
        "match": "unknown",
        "hash": None,
        "virustotal": {}
    }

    for known_sig, extensions in SIGNATURES.items():
        if known_sig in sig:
            result["match"] = "OK" if ext in extensions else "Mismatch"
            break

    file_hash = hash_file(file_path)
    result["hash"] = file_hash

    if api_key and file_hash:
        result["virustotal"] = vt_lookup(file_hash, api_key)

    return result

def scan_directory(target_dir, api_key=None):
    results = []
    print(f"\n🔍 Scanning: {target_dir}\n")

    for root, _, files in os.walk(target_dir):
        for file in files:
            path = os.path.join(root, file)
            info = check_signature(path, api_key)

            status = info["match"]
            if status == "OK":
                print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} {file} -> {info['signature']}")
            elif status == "Mismatch":
                print(f"{Fore.RED}[!!]{Style.RESET_ALL} {file} -> Signature: {info['signature']}, Ext: {info['extension']}")
            else:
                print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} {file} -> {info['signature']}")

            results.append(info)
    return results

def save_output(data, output_path, format="json"):
    with open(output_path, "w", newline='') as f:
        if format == "json":
            json.dump(data, f, indent=4)
        elif format == "csv":
            keys = list(data[0].keys())
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(data)
    print(f"\n📁 Output saved to {output_path}")

def get_vt_api_key(file_path="vt_api_key.txt"):
    try:
        with open(file_path, "r") as f:
            return f.read().strip()
    except:
        return None

def main():
    parser = argparse.ArgumentParser(description="🔍 File Signature vs Extension Checker + VT Lookup")
    parser.add_argument("--path", "-p", required=True, help="Directory to scan")
    parser.add_argument("--json", help="Save output to JSON file")
    parser.add_argument("--csv", help="Save output to CSV file")
    parser.add_argument("--vt", action="store_true", help="Enable VirusTotal lookup (requires API key)")

    args = parser.parse_args()

    if not os.path.exists(args.path):
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Path does not exist: {args.path}")
        return

    api_key = get_vt_api_key() if args.vt else None

    results = scan_directory(args.path, api_key)

    if args.json:
        save_output(results, args.json, format="json")
    if args.csv:
        save_output(results, args.csv, format="csv")

if __name__ == "__main__":
    main()
