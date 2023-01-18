Timeroast and Trustroast scripts
================================

Python scripts accompanying the blog post _Timeroasting, trustroasting and computer spraying: taking advantage of weak computer and trust account passwords in Active Directory_. These support the _timeroasting_ and _trustroasting_ attack techniques by discovering weak computer or trust passwords within an Active Directory domain.

How to run
----------

Both scripts require Python 3.6 or higher. No installation is required. The Timeroasting scripts have no further 
dependencies and the Trustroast scripts solely depends on [Impact](https://github.com/fortra/impacket).

Run each script with `-h` for usage instructions.

Timeroasting
------------

![Timeroasting example screenshot](img1.png)

Timeroasting takes advantage of the Windows' NTP authentication mechanism, allowing unauthenticated attackers to effectively request a password hash of any computer account by sending an NTP request with that account's RID. This is not a problem when computer accounts are properly generated, but if a non-standard or legacy default password is set this tool allows you to brute-force those offline.

Two scripts are included:

- `timeroast.py`: given a DC domain name or IP, will attempt to get 'NTP hashes' of the computer accounts in the domain by enumerating RID's. Requires root privileges in order to be able to receive NTP responses.
- `timecrack.py`: performs a simple, unoptimized, dictionary attack on the results of `timeroast.py`. 

I am currently looking at getting support for Timeroasted hashes into an optimized hash cracking tool. If that succeeds, I will add support for that tool's input format and `timecrack.py` will become obsolete.


Trustroasting
-------------

![Example screenshot of kirbi_to_hashcat.py](img2.png)

I currently have not implemented a convenient `trustroast.py` script that will automatically enumerate trusts and fetch tickets. However, this can easily be achieved with [Rubeus](https://github.com/GhostPack/Rubeus) in the way described in the blog post. I did add a simple script which converts Rubeus' output format into something you can slot into Hashcat:

- `kirbi_to_hashcat.py`: converts a Kerberos ticket (referall/trust, service, ticket-granting, etc.) that is encoded as a base64 KRB_CRED structure into a Hashcat format. Hash types 13100, 19600, 19700 (RC-4 and AES tickets) are supported.