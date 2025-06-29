Timeroast scripts
=================

Python and Powershell scripts accompanying the whitepaper [Timeroasting, trustroasting and computer spraying: taking advantage of weak computer and trust account passwords in Active Directory](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf). These support the _timeroasting_ attack technique, which abuses the NTP protocol in order to extract password hashes for computer and trust accounts from a domain controller, which can then be attempted to be cracked offline. It turns out it is not uncommon for such accounts to have bad (default) passwords instead of the frequently rotated random passwords that are normally used, making password cracking possible in those cases.

How to run
----------

Both the Python (`timeroast.py`) and Powershell (`timeroast.ps1`) scripts should run standalone with no need to install
any dependencies. The Python script requires Python 3.6.

The `extra-scripts/kirbi_to_hashcat.py` script solely depends on [Impacket](https://github.com/fortra/impacket).

Execute `python timeroast.py -h` or `powershell timeroast.ps1 -?` for usage instructions.

Timeroasting
------------

Timeroasting takes advantage of Windows' NTP authentication mechanism, allowing unauthenticated attackers to effectively request a password hash of any computer or trust account by sending an NTP request with that account's RID. This is not a problem when computer accounts are properly generated, but if a non-standard or legacy default password is set this tool allows you to brute-force those offline.

Three scripts are included:

- `timeroast.py`: given a DC domain name or IP, will attempt to get 'NTP hashes' of the computer/trust accounts in the domain by enumerating RID's.
- `timeroast.ps1`: Powershell port of the same script.
- `extra-scripts/timecrack.py`: performs a simple, unoptimized, dictionary attack on the results of `timeroast.py` or `timeroast.ps1`. 

Hashcat [will add support for Timeroast hashes](https://github.com/hashcat/hashcat/issues/3629) as hash type 31300. Currently, it's already available in the [beta release](https://hashcat.net/beta/).


Alternative ways to abuse weak 'dollar account' passwords
---------------------------------------------------------

If Timeroasting is not possible or desirable, there are some alternative attacks that can be used to identity and compromise computer or trust accounts with weak passwords. These are described in detail in 
[the whitepaper](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf). To summarize, these attacks 
work as follows:

1. _computer spraying_: perform a password spray for computer accounts, where you try a legacy NT password (up to first 14 characters of the computer name, lowercased, without the dollar sign) for each computer account.
2. _extended kerberoasting_: adjust a Kerberoasting tool to also fetch computer and trust tickets. Requires an AD account.
3. _trustroasting_: obtain a trust ticket through a regular Kerberos referal, and brute-force the password used to encrypt it. Requires an AD account.

Computer spraying and Kerberoasting can easily be carried out with existing tools. I currently have not implemented a convenient `trustroast.py` script that will automatically enumerate trusts and fetch tickets. However, this can easily be achieved with [Rubeus](https://github.com/GhostPack/Rubeus) in the way described in the whitepaper. However, I did add a simple script which converts Rubeus' output format into something you can slot into Hashcat:

- `extra-scripts/kirbi_to_hashcat.py`: converts a Kerberos ticket (referal/trust, service, ticket-granting, etc.) that is encoded as a base64 KRB_CRED structure into Hashcat format. Hash types 13100, 19600, 19700 (i.e. RC-4 and AES tickets) are supported.

---

Credits
-------

The attack and original script were developed by Tom Tervoort of Secura BV.

The Powershell port was contributed by [Jacopo Scannella](https://github.com/antipatico).

Special thanks to [Garret Foster](https://www.optiv.com/blog/author/garrett-foster) for pointing out that Timeroasting can also be used to obtain trust account hashes.

---

### 🔧 Enhancements by B4l3rI0n

Several improvements were made to `extra-scripts/timecrack.py` to significantly improve usability and performance:

#### ✅ UnicodeDecodeError Fix for rockyou.txt

The original script crashed when using non-UTF-8 encoded dictionaries such as `rockyou.txt`.
I fixed this by opening the dictionary file using the `latin-1` encoding to support special characters:

```python
open('rockyou.txt', 'r', encoding='latin-1')
```

#### 🚀 Performance Optimization: Multicore Cracking

The original `timecrack.py` used a naive nested loop, which was very slow for large wordlists.
I rewrote the script to use **Python’s multiprocessing module**, utilizing all available CPU cores to crack hashes in parallel. This dramatically increases performance, especially with large lists like `rockyou.txt`.

Key features:

* Parallel cracking of each hash using `multiprocessing.Pool`
* Automatically uses all available cores (`--workers` flag customizable)
* Automatically skips to the next hash once a password match is found

Usage:

```bash
python3 timecrack.py hashes.txt /usr/share/wordlists/rockyou.txt
```

Or customize CPU cores:

```bash
python3 timecrack.py hashes.txt /usr/share/wordlists/rockyou.txt --workers 8
```
![image](https://github.com/user-attachments/assets/fbb58163-61db-4e32-9d23-8c8b3cec5b45)

#### 🧠 Author of Optimizations:

Contributed by [B4l3rI0n](https://github.com/B4l3rI0n)
