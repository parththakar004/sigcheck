---
A lightweight, CLI-based digital forensic utility to detect mismatches between file **extensions** and actual **file signatures (magic numbers)**. Includes optional **VirusTotal hash scanning**, with support for exporting results to **JSON** or **CSV**.
---

## 🚀 Features

- ✅ Scan any directory recursively
- 🔍 Detect mismatched extensions vs actual file type
- 🔐 SHA-256 hashing
- 🧪 Optional VirusTotal integration
- 📁 Export to JSON or CSV
- 🎯 Works on Kali Linux and other Linux distros

---

## 📦 Installation

```bash
git clone https://github.com/yourusername/sigcheck.git
cd sigcheck
pip install -r requirements.txt
chmod +x sigcheck.py
```
---
```🔧 Usage
./sigcheck.py --path /path/to/scan 
```
---
```With output:
./sigcheck.py --path ./evidence --json result.json --csv result.csv
```
---
```With VirusTotal:

./sigcheck.py --path ./evidence --vt
```
💡 Place your VirusTotal API key inside a file named vt_api_key.txt in the same directory.
---

```📋 Sample Output
[OK] photo.jpg -> JPEG image data
[!!] suspicious.doc -> Signature: Zip archive data, Ext: .doc
[?] unknown.xyz -> Unknown or unsupported type
```
---
🧪 VirusTotal API Setup

Sign up at virustotal.com
Get your API key from your profile.
Save the key in a file called vt_api_key.txt.
---
👨‍💻 Author
Made with 💻 by Parth Thakar
