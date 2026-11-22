"""
Generate fresh secrets for MediGuard AI and print the lines to paste into .env.

Usage (from the project folder):
    python tools/make_secrets.py

You will be asked for the Doctor and SOC dashboard passwords. Only their hashes
are printed, so the real passwords are never stored in any file.

After running it:
  1. Paste the printed lines into .env (replace the old values).
  2. Put the SAME MEDIGUARD_HMAC_SECRET value into secrets.h on the ESP32 and re-flash it.
  3. Put the SAME MEDIGUARD_HMAC_SECRET value into the attack-test folder's .env.
"""
import getpass
import secrets

from werkzeug.security import generate_password_hash


def ask_password(role):
    while True:
        first = getpass.getpass(f"New {role} password (min 10 characters): ")
        if len(first) < 10:
            print("Too short, try again.")
            continue
        if first != getpass.getpass(f"Repeat {role} password: "):
            print("Passwords do not match, try again.")
            continue
        return first


def main():
    doctor_hash = generate_password_hash(ask_password("Doctor"))
    soc_hash = generate_password_hash(ask_password("SOC"))
    print("\n# ---- paste these lines into .env ----")
    print(f"MEDIGUARD_HMAC_SECRET={secrets.token_hex(32)}")
    print(f"MEDIGUARD_FLASK_SECRET_KEY={secrets.token_hex(32)}")
    print(f"MEDIGUARD_DOCTOR_PASSWORD_HASH={doctor_hash}")
    print(f"MEDIGUARD_SOC_PASSWORD_HASH={soc_hash}")
    print("MEDIGUARD_DEBUG=0")


if __name__ == "__main__":
    main()
