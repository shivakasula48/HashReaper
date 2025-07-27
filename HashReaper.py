import hashlib
import itertools
import string
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
import argparse
import os
import sys
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Optional imports with fallback
try:
    import bcrypt
except ImportError:
    bcrypt = None
    print(Fore.YELLOW + "[!] bcrypt not installed. bcrypt hashes will be skipped.")

try:
    import scrypt
except ImportError:
    scrypt = None
    print(Fore.YELLOW + "[!] scrypt not installed. scrypt hashes will be skipped.")

try:
    from passlib.hash import lmhash
except ImportError:
    lmhash = None
    print(Fore.YELLOW + "[!] passlib not installed. LM hashes will be skipped.")

# Supported hash types
HASH_TYPES = [
    'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512',
    'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512',
    'ntlm', 'bcrypt', 'scrypt', 'pbkdf2_sha256', 'lm'
]

DEFAULT_CHARSET = string.ascii_letters + string.digits + string.punctuation

class HashCracker:
    def __init__(self):
        self.running = True

    @staticmethod
    def ntlm_hash(password):
        return hashlib.new('md4', password.encode('utf-16le')).hexdigest()

    def check_bcrypt(self, password, target_hash):
        if bcrypt is None:
            raise ImportError("Install bcrypt: pip install bcrypt")
        return bcrypt.checkpw(password.encode(), target_hash.encode())

    def check_scrypt(self, password, target_hash):
        if scrypt is None:
            raise ImportError("Install scrypt: pip install scrypt")
        salt = b'salt123'  # Replace with actual salt if known
        derived_hash = scrypt.hash(password.encode(), salt, N=16384, r=8, p=1)
        return derived_hash.hex() == target_hash

    @staticmethod
    def check_pbkdf2(password, target_hash):
        salt = b'salt123'  # Replace with actual salt if known
        derived_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000).hex()
        return derived_hash == target_hash

    def lm_hash(self, password):
        if lmhash is None:
            raise ImportError("Install passlib: pip install passlib")
        return lmhash.hash(password)

    def check_hash(self, hash_fn, password, target_hash, hash_type):
        try:
            if hash_type == 'ntlm':
                return self.ntlm_hash(password) == target_hash
            elif hash_type == 'bcrypt':
                return self.check_bcrypt(password, target_hash)
            elif hash_type == 'scrypt':
                return self.check_scrypt(password, target_hash)
            elif hash_type == 'pbkdf2_sha256':
                return self.check_pbkdf2(password, target_hash)
            elif hash_type == 'lm':
                return self.lm_hash(password) == target_hash
            else:
                if hash_fn is None:
                    raise ValueError(f"Unsupported hash type: {hash_type}")
                return hash_fn(password.encode()).hexdigest() == target_hash
        except Exception as e:
            print(Fore.RED + f"[!] Error checking hash: {e}")
            return False

    def crack_hash(self, target_hash, hash_type='md5', wordlist=None, 
                  min_length=1, max_length=8, charset=DEFAULT_CHARSET, 
                  max_workers=4):
        if hash_type not in HASH_TYPES:
            raise ValueError(f"Unsupported hash type: {hash_type}")

        # Get hash function
        hash_fn = None
        if hash_type not in ['ntlm', 'bcrypt', 'scrypt', 'pbkdf2_sha256', 'lm']:
            hash_fn = getattr(hashlib, hash_type, None)

        # Wordlist mode
        if wordlist:
            try:
                with open(wordlist, 'r', errors='ignore') as f:
                    passwords = [line.strip() for line in f]
                    total = len(passwords)
                    print(Fore.CYAN + f"[*] Trying {total} passwords...")

                    with ThreadPoolExecutor(max_workers=max_workers) as executor:
                        futures = {}
                        for pwd in passwords:
                            if not self.running:
                                break
                            future = executor.submit(
                                self.check_hash, hash_fn, pwd, target_hash, hash_type
                            )
                            futures[future] = pwd

                        for future in tqdm(futures, total=total, desc="Cracking"):
                            if future.result():
                                return futures[future]
            except Exception as e:
                print(Fore.RED + f"[!] Wordlist error: {e}")
                return None

        # Brute-force mode
        else:
            total = sum(len(charset) ** length for length in range(min_length, max_length + 1))
            print(Fore.CYAN + f"[*] Brute-forcing (lengths {min_length}-{max_length})...")

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                for length in range(min_length, max_length + 1):
                    for pwd in tqdm(itertools.product(charset, repeat=length), 
                                  total=len(charset) ** length, 
                                  desc=f"Length {length}"):
                        if not self.running:
                            return None
                        pwd_str = ''.join(pwd)
                        if self.check_hash(hash_fn, pwd_str, target_hash, hash_type):
                            return pwd_str

        return None

def interactive_mode():
    print(Fore.CYAN + "\n=== Interactive Hash Cracker ===")
    target_hash = input(Fore.YELLOW + "Enter target hash: ").strip()
    if not target_hash:
        print(Fore.RED + "Error: Hash cannot be empty!")
        return

    print(Fore.YELLOW + f"Supported hash types: {', '.join(HASH_TYPES)}")
    hash_type = input("Enter hash type (default: md5): ").strip().lower() or "md5"

    method = input(Fore.YELLOW + "Method (1: Wordlist, 2: Brute-force): ").strip()
    wordlist = None
    min_length, max_length = 1, 8

    if method == "1":
        wordlist = input(Fore.YELLOW + "Wordlist path: ").strip()
        if not os.path.exists(wordlist):
            print(Fore.RED + "Error: Wordlist not found!")
            return
    elif method == "2":
        try:
            min_length = int(input(Fore.YELLOW + "Min length: ").strip() or 1)
            max_length = int(input(Fore.YELLOW + "Max length: ").strip() or 8)
        except ValueError:
            print(Fore.RED + "Error: Invalid length!")
            return
    else:
        print(Fore.RED + "Error: Invalid method!")
        return

    print(Fore.CYAN + "\n[*] Cracking...")
    cracker = HashCracker()
    result = cracker.crack_hash(target_hash, hash_type, wordlist, min_length, max_length)

    print(Fore.GREEN + f"\n[+] Password found: {result}" if result else Fore.RED + "\n[!] Password not found.")

def main():
    parser = argparse.ArgumentParser(description="Advanced Hash Cracker")
    parser.add_argument('hash', nargs='?', help="Target hash (leave empty for interactive mode)")
    parser.add_argument('-t', '--hash_type', default='md5', help=f"Hash type (default: md5). Supported: {HASH_TYPES}")
    parser.add_argument('-w', '--wordlist', help="Wordlist file")
    parser.add_argument('--min', type=int, default=1, help="Min password length (brute-force)")
    parser.add_argument('--max', type=int, default=8, help="Max password length (brute-force)")
    parser.add_argument('-c', '--charset', default=DEFAULT_CHARSET, help="Character set (brute-force)")
    parser.add_argument('--threads', type=int, default=4, help="Max threads")

    args = parser.parse_args()

    if not args.hash:
        interactive_mode()
    else:
        cracker = HashCracker()
        result = cracker.crack_hash(
            args.hash, args.hash_type, args.wordlist,
            args.min, args.max, args.charset, args.threads
        )
        print(Fore.GREEN + f"[+] Password found: {result}" if result else Fore.RED + "[!] Password not found.")

if __name__ == "__main__":
    main()
