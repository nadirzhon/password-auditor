#!/usr/bin/env python3
"""
Password Auditor - Hash cracker + policy analyzer + mutation engine
Author: nadirzhon | github.com/nadirzhon
"""

import hashlib
import argparse
import hmac
import requests
import re
from colorama import Fore, Style, init

init(autoreset=True)

LEET = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}
COMMON_SUFFIXES = ["123", "!", "1", "2024", "2025", "#", "@", "1234"]
SQLI_ERRORS = ["sql syntax", "mysql_fetch", "ORA-", "sqlite3"]

def hash_string(s, hash_type):
    s = s.encode()
    algos = {"md5": hashlib.md5, "sha1": hashlib.sha1,
             "sha256": hashlib.sha256, "sha512": hashlib.sha512}
    if hash_type in algos:
        return algos[hash_type](s).hexdigest()
    return None

def generate_mutations(word):
    mutations = set([word.upper(), word.capitalize(), word.lower()])
    leet = word
    for char, rep in LEET.items():
        leet = leet.replace(char, rep)
    mutations.add(leet)
    for suffix in COMMON_SUFFIXES:
        mutations.add(word + suffix)
        mutations.add(word.capitalize() + suffix)
    mutations.add(word[::-1])
    mutations.add(word + word)
    return mutations

def crack_hash(target_hash, hash_type, wordlist_path):
    print(f"{Fore.CYAN}[*] Cracking {hash_type.upper()}: {target_hash}{Style.RESET_ALL}")
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f):
                word = line.strip()
                if hash_string(word, hash_type) == target_hash:
                    print(f"{Fore.GREEN}[+] CRACKED: {word} (attempt #{i+1})")
                    return word
                for mut in generate_mutations(word):
                    if hash_string(mut, hash_type) == target_hash:
                        print(f"{Fore.GREEN}[+] CRACKED (mutation): {mut}")
                        return mut
                if i % 10000 == 0 and i > 0:
                    print(f"  Tried {i} passwords...", end="\r")
    except FileNotFoundError:
        print(f"{Fore.RED}[-] Wordlist not found: {wordlist_path}")
    print(f"{Fore.RED}[-] Not cracked")
    return None

def analyze_password(password):
    checks = [
        (len(password) >= 8,  "Length >= 8 chars",  10),
        (len(password) >= 12, "Length >= 12 chars",  10),
        (len(password) >= 16, "Length >= 16 chars",  10),
        (bool(re.search(r"[A-Z]", password)), "Uppercase",  10),
        (bool(re.search(r"[a-z]", password)), "Lowercase",  10),
        (bool(re.search(r"\d",   password)), "Digits",      10),
        (bool(re.search(r"[!@#$%^&*()_+\-=]", password)), "Special chars", 20),
        (password.lower() not in ["password","123456","qwerty","admin"], "Not common", 20),
    ]
    score = 0
    for passed, label, pts in checks:
        mark = f"{Fore.GREEN}✓" if passed else f"{Fore.RED}✗"
        print(f"  {mark} {label}{Style.RESET_ALL}")
        if passed:
            score += pts
    strength = "STRONG" if score >= 80 else "MODERATE" if score >= 50 else "WEAK"
    color = Fore.GREEN if score >= 80 else Fore.YELLOW if score >= 50 else Fore.RED
    print(f"\n  Score: {score}/100 | {color}{strength}{Style.RESET_ALL}")
    return score

def check_hibp(password):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    r = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}",
                     headers={"Add-Padding": "true"}, timeout=10)
    for line in r.text.splitlines():
        h, count = line.split(":")
        if h == suffix:
            print(f"{Fore.RED}[!] PWNED: {count} times in breach databases!")
            return int(count)
    print(f"{Fore.GREEN}[+] Not found in breach databases")
    return 0

def main():
    parser = argparse.ArgumentParser(description="Password Auditor")
    sub = parser.add_subparsers(dest="command")

    c = sub.add_parser("crack")
    c.add_argument("--hash", required=True)
    c.add_argument("--type", choices=["md5","sha1","sha256","sha512"], default="md5")
    c.add_argument("--wordlist", required=True)

    a = sub.add_parser("audit")
    a.add_argument("--password", required=True)

    m = sub.add_parser("mutate")
    m.add_argument("--word", required=True)
    m.add_argument("--output")

    h = sub.add_parser("hibp")
    h.add_argument("--password", required=True)

    args = parser.parse_args()
    if args.command == "crack":
        crack_hash(args.hash, args.type, args.wordlist)
    elif args.command == "audit":
        analyze_password(args.password)
    elif args.command == "mutate":
        muts = generate_mutations(args.word)
        if args.output:
            with open(args.output, "w") as f:
                f.write("\n".join(muts))
            print(f"[+] {len(muts)} mutations -> {args.output}")
        else:
            for m in muts:
                print(m)
    elif args.command == "hibp":
        check_hibp(args.password)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
