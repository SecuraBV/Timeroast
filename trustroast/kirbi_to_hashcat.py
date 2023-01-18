#!/usr/bin/env python3

"""Simple script that extracts the first ticket from a base64 encoded KRB_CRED structure (i.e. Rubeus' asktgs 
output) and then outputs it in Hashcat format"""

from pyasn1.codec.der import decoder
from impacket.krb5.asn1 import KRB_CRED
from binascii import hexlify
import sys
from base64 import b64encode, b64decode
from argparse import ArgumentParser, RawDescriptionHelpFormatter, FileType

argparser = ArgumentParser(formatter_class=RawDescriptionHelpFormatter, description=\
"""Converts a Kerberos ticket from a base64 encoded KRB_CRED format to a Hashcat
$krb5tgs$ hash. The main use case is brute-forcing trust passwords based on a 
trust ticket retrieved with a tool such as Rubeus.

If the KRB_CRED input contains multiple tickets, the first one is taken. Output 
is written to STDOUT.
""")
argparser.add_argument('file', type=FileType('r'), default=sys.stdin, nargs='?', \
  help='Input file (STDIN if omitted)')
args = argparser.parse_args()

# Parse base64 encoded KRB_CRED.
data = b64decode(args.file.read())
creds = decoder.decode(data, asn1Spec=KRB_CRED())[0]

# Take the first ticket from the store.
ticket = creds['tickets'][0]

# Extract components relevant for cracking.
realm = ticket['realm']
sname = '/'.join(str(s) for s in ticket['sname']['name-string'])
enctype = ticket['enc-part']['etype']
ciphertext = hexlify(ticket['enc-part']['cipher'].asOctets()).decode()

if enctype == 23:
  # RC4 ticket.
  print(f'$krb5tgs${enctype}$*USERNAME${realm}${sname}*${ciphertext[:32]}${ciphertext[32:]}')
elif enctype == 17 or enctype == 18:
  # AES ticket.
  print(f'$krb5tgs${enctype}$USERNAME${realm}$*{sname}*${ciphertext[:32]}${ciphertext[32:]}')
else:
  raise Exception(f'Unsupported encryption type: {enctype}')
