#!/usr/bin/env python3

from binascii import unhexlify
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from multiprocessing import Pool, cpu_count
import hashlib, re, sys

HASH_FORMAT = r'^(?P<rid>\d+):\$sntp-ms\$(?P<hashval>[0-9a-f]{32})\$(?P<salt>[0-9a-f]{96})$'

def md4(data: bytes) -> bytes:
    try:
        return hashlib.new('md4', data).digest()
    except ValueError:
        from md4 import MD4
        return MD4(data).bytes()

def compute_hash(password: str, salt: bytes) -> bytes:
    return hashlib.md5(md4(password.encode('utf-16le')) + salt).digest()

def crack_one(args):
    rid, hashval, salt, password = args
    if compute_hash(password, salt) == hashval:
        return (rid, password)
    return None

def load_hashes(hashfile):
    hashes = []
    for line in open(hashfile, 'r'):
        line = line.strip()
        if line:
            m = re.match(HASH_FORMAT, line)
            if not m:
                print(f'[!] Invalid hash format: {line}', file=sys.stderr)
                sys.exit(1)
            rid, hashval, salt = m.group('rid', 'hashval', 'salt')
            hashes.append((int(rid), unhexlify(hashval), unhexlify(salt)))
    return hashes

def main():
    argparser = ArgumentParser(formatter_class=RawDescriptionHelpFormatter, description=
"""Multicore-optimized Timeroast cracker.

Uses multiprocessing to crack legacy SNTP hashes faster by utilizing all CPU cores.
""")
    argparser.add_argument('hashes', help='File with hashes from timeroast.py')
    argparser.add_argument('dictionary', help='Line-delimited password dictionary (rockyou.txt etc.)')
    argparser.add_argument('--workers', type=int, default=cpu_count(), help='Number of CPU cores to use')
    args = argparser.parse_args()

    hashes = load_hashes(args.hashes)
    wordlist = open(args.dictionary, 'r', encoding='latin-1', errors='ignore').read().splitlines()
    
    crackcount = 0
    found = []

    with Pool(args.workers) as pool:
        for rid, hashval, salt in hashes:
            print(f'[+] Cracking RID {rid}...')
            jobs = ((rid, hashval, salt, pwd) for pwd in wordlist)
            for result in pool.imap_unordered(crack_one, jobs, chunksize=500):
                if result:
                    crackcount += 1
                    found.append(result)
                    print(f'[✓] Cracked RID {result[0]}: {result[1]}')
                    break  # Stop after first match for that hash

    print(f'\n[+] Done. {crackcount} password(s) cracked:')
    for rid, password in found:
        print(f'    RID {rid}: {password}')

if __name__ == '__main__':
    main()
 
