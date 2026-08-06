# 🔐 Password Auditor

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white) ![License](https://img.shields.io/badge/License-MIT-green) ![Tests](https://img.shields.io/badge/tests-passing-success) ![Status](https://img.shields.io/badge/status-active-brightgreen)

Password security tool: hash cracking, policy enforcement, wordlist mutation, HaveIBeenPwned check.

## Features
- Hash cracking: MD5, SHA1, SHA256, SHA512 (dictionary + mutations)
- NIST SP 800-63B policy analyzer
- Leet-speak, case, suffix/prefix mutation engine
- HaveIBeenPwned k-anonymity API check

## Usage
```bash
pip install -r requirements.txt

python auditor.py crack --hash 5f4dcc3b5aa765d61d8327deb882cf99 --type md5 --wordlist rockyou.txt
python auditor.py audit --password "MyP@ssw0rd123"
python auditor.py mutate --word "company2024" --output mutations.txt
python auditor.py hibp --password "password123"
```

## Responsible use

This project is published for **defensive research, education, and authorized security testing only**.
Use it exclusively on systems you own or have explicit written permission to assess. The author
assumes no liability for misuse. See `SECURITY.md` for the disclosure policy.
