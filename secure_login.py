import os
import json
import time
import hmac
import hashlib
import secrets
import base64
import struct
import getpass
import tempfile
import urllib.parse
from pathlib import Path

# ---------------- CONFIGURATION ----------------

DB_FILE = Path("users.json")
MAX_ATTEMPTS = 5
LOCKOUT_TIME = 60
PBKDF2_ITERATIONS = 600_000
OTP_INTERVAL = 30
OTP_DIGITS = 6

# ---------------- DATABASE ----------------

def load_users():
    if not DB_FILE.exists():
        return {}

    try:
        with open(DB_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)
            if not isinstance(data, dict):
                raise ValueError("Invalid database format")
            return data
    except (json.JSONDecodeError, ValueError):
        raise RuntimeError("User database is corrupted.")


def save_users(users):
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)

    fd, temp_name = tempfile.mkstemp(
        dir=DB_FILE.parent,
        prefix=".users_",
        suffix=".tmp"
    )

    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)

        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(users, file, indent=4)
            file.flush()
            os.fsync(file.fileno())

        os.replace(temp_name, DB_FILE)

        if os.name == "posix":
            os.chmod(DB_FILE, 0o600)

    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


# ---------------- PASSWORD HASHING ----------------

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_bytes(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS
    )

    return (
        base64.b64encode(salt).decode(),
        base64.b64encode(password_hash).decode()
    )


def verify_password(password, salt, stored_hash):
    salt_bytes = base64.b64decode(salt)
    _, calculated_hash = hash_password(password, salt_bytes)

    return hmac.compare_digest(
        calculated_hash,
        stored_hash
    )


# ---------------- TOTP AUTHENTICATION ----------------

def generate_totp_secret():
    return base64.b32encode(
        secrets.token_bytes(20)
    ).decode("ascii").rstrip("=")


def generate_totp(secret, timestamp=None):
    if timestamp is None:
        timestamp = time.time()

    padded_secret = secret + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded_secret)

    counter = int(timestamp // OTP_INTERVAL)
    message = struct.pack(">Q", counter)

    digest = hmac.new(
        key,
        message,
        hashlib.sha1
    ).digest()

    offset = digest[-1] & 0x0F

    binary_code = struct.unpack(
        ">I",
        digest[offset:offset + 4]
    )[0] & 0x7FFFFFFF

    otp = binary_code % (10 ** OTP_DIGITS)

    return f"{otp:0{OTP_DIGITS}d}"


def verify_totp(secret, user_otp, last_step=-1):
    if not user_otp.isdigit() or len(user_otp) != OTP_DIGITS:
        return None

    current_step = int(time.time() // OTP_INTERVAL)

    # Allow a 30-second clock difference in either direction.
    for step in range(current_step - 1, current_step + 2):
        if step <= last_step or step < 0:
            continue

        expected = generate_totp(
            secret,
            timestamp=step * OTP_INTERVAL
        )

        if hmac.compare_digest(expected, user_otp):
            return step

    return None


def generate_setup_uri(username, secret):
    issuer = "SecureCLI"
    label = urllib.parse.quote(f"{issuer}:{username}")
    params = urllib.parse.urlencode({
        "secret": secret,
        "issuer": issuer,
        "algorithm": "SHA1",
        "digits": OTP_DIGITS,
        "period": OTP_INTERVAL
    })

    return f"otpauth://totp/{label}?{params}"


# ---------------- REGISTRATION ----------------

def register():
    users = load_users()

    print("\n========== USER REGISTRATION ==========")

    username = input("Enter username: ").strip().lower()

    if not username or len(username) > 64:
        print("Invalid username.")
        return

    if username in users:
        print("Username already exists.")
        return

    password = getpass.getpass("Create password: ")

    if len(password) < 12:
        print("Password must contain at least 12 characters.")
        return

    confirm = getpass.getpass("Confirm password: ")

    if password != confirm:
        print("Passwords do not match.")
        return

    salt, password_hash = hash_password(password)

    # Generate unique TOTP secret
    totp_secret = generate_totp_secret()

    users[username] = {
        "salt": salt,
        "password_hash": password_hash,
        "totp_secret": totp_secret,
        "failed_attempts": 0,
        "locked_until": 0,
        "last_totp_step": -1
    }

    save_users(users)

    print("\nRegistration successful!")
    print("\nConfigure your authenticator application.")
    print("TOTP SECRET:", totp_secret)
    print("\nProvisioning URI:")
    print(generate_setup_uri(username, totp_secret))
    print("\nAdd this account to your authenticator app.")
    print("Keep the secret private and do not share it.")


# ---------------- LOGIN SYSTEM ----------------

def login():
    users = load_users()

    print("\n========== SECURE LOGIN ==========")

    username = input("Username: ").strip().lower()
    password = getpass.getpass("Password: ")

    user = users.get(username)

    if user is None:
        # Perform a dummy password derivation to reduce
        # timing differences for nonexistent accounts.
        hash_password(password, b"dummy-salt-12345")
        print("Invalid username or password.")
        return

    current_time = time.time()

    if current_time < user["locked_until"]:
        remaining = int(user["locked_until"] - current_time)
        print(f"Account temporarily locked. Try again in {remaining + 1} seconds.")
        return

    # Verify password
    if not verify_password(
        password,
        user["salt"],
        user["password_hash"]
    ):
        user["failed_attempts"] += 1

        if user["failed_attempts"] >= MAX_ATTEMPTS:
            user["locked_until"] = current_time + LOCKOUT_TIME
            user["failed_attempts"] = 0

            print("Too many failed attempts!")
            print("Account locked for 60 seconds.")
        else:
            remaining = MAX_ATTEMPTS - user["failed_attempts"]
            print(f"Invalid password. Attempts remaining: {remaining}")

        save_users(users)
        return

    # Verify TOTP
    otp = getpass.getpass("Enter 6-digit authenticator code: ")

    accepted_step = verify_totp(
        user["totp_secret"],
        otp,
        user.get("last_totp_step", -1)
    )

    if accepted_step is None:
        user["failed_attempts"] += 1

        if user["failed_attempts"] >= MAX_ATTEMPTS:
            user["locked_until"] = current_time + LOCKOUT_TIME
            user["failed_attempts"] = 0

            print("Too many failed attempts!")
            print("Account locked for 60 seconds.")
        else:
            remaining = MAX_ATTEMPTS - user["failed_attempts"]
            print(f"Invalid OTP. Attempts remaining: {remaining}")

        save_users(users)
        return

    # Successful authentication
    user["failed_attempts"] = 0
    user["locked_until"] = 0
    user["last_totp_step"] = accepted_step

    save_users(users)

    print("\n================================")
    print(" LOGIN SUCCESSFUL!")
    print(" TWO-FACTOR AUTHENTICATION PASSED")
    print(f" Welcome, {username}!")
    print("================================")


# ---------------- MAIN MENU ----------------

def main():
    while True:
        print("\n================================")
        print("     SECURE CLI LOGIN SYSTEM")
        print("================================")
        print("1. Register")
        print("2. Login")
        print("3. Exit")

        choice = input("\nEnter your choice: ").strip()

        try:
            if choice == "1":
                register()

            elif choice == "2":
                login()

            elif choice == "3":
                print("Exiting Secure Login System...")
                break

            else:
                print("Invalid choice. Try again.")

        except (OSError, RuntimeError, ValueError) as error:
            print(f"Operation failed: {error}")


if __name__ == "__main__":
    main()
