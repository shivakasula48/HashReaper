# 💀 HashReaper

**HashReaper** is a powerful, multi-threaded hash cracking tool designed for cybersecurity professionals, ethical hackers, and enthusiasts. It supports a wide range of hashing algorithms and provides both brute-force and dictionary-based attacks.

---

## 🚀 Features

- 🔐 Supports 14+ hash types (`md5`, `sha1`, `ntlm`, `bcrypt`, etc.)
- 🧠 Smart detection and validation of inputs
- ⚡ Multithreaded cracking with real-time progress
- 🎨 Color-coded and user-friendly terminal output
- 🛠️ Interactive and command-line modes
- 🧩 Dependency fallback system for missing libraries

---

## 🧬 Supported Hash Types

- `md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512`
- `sha3_224`, `sha3_256`, `sha3_384`, `sha3_512`
- `ntlm`, `bcrypt`, `scrypt`, `pbkdf2_sha256`, `lm`

> ✅ Note: Some hashes (like `bcrypt`, `scrypt`, `lm`) require optional libraries.

---

## 💻 Installation

### Clone the repository:
```bash
git clone https://github.com/shivakasula48/HashReaper.git
cd HashReaper


```
### Install dependencies:

```bash
pip install -r requirements.txt
```
---
## 🔧 Usage

### Interactive Mode:
```bash
python hashreaper.py
```
### Command-Line Mode:
```bash
python hashreaper.py <target_hash> -t <hash_type> [-w wordlist.txt] [--min 1 --max 6] [-c charset] [--threads 4]
```
### Example:
```bash
python hashreaper.py 5f4dcc3b5aa765d61d8327deb882cf99 -t md5 -w wordlists/common.txt
```
---

## 📁 Directory Structure
```tree
HashReaper/
├── hashreaper.py
├── requirements.txt
├── README.md
├── LICENSE
├── sample.txt
└── passwords.txt
```
---

## 🛡️ Legal Disclaimer

This tool is intended for **educational** and **ethical purposes** only.
Unauthorized usage against systems you do not own or have permission to test is illegal and prohibited.

---

## 🙌 Author

**Kasula Shiva**  
🎓 B.Tech CSE (Cybersecurity)  
🔗 GitHub: [shivakasula48](https://github.com/shivakasula48)  
📧 Email: [shivakasula10@gmail.com](mailto:shivakasula10@gmail.com)

---

## 📜 License

This project is open-source and free to use by anyone for personal or educational purposes.  
Feel free to modify, distribute, and use the code as long as proper credit is given to the original author, **Kasula Shiva**.

