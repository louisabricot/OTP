import argparse
import logging
import sys
import os
import stat
from cryptography.fernet import Fernet
import hashlib
from datetime import datetime, timezone
import hmac
from math import floor
import base64
master_key_file = "ft_otp.key"


#t0 = 0
#X = interval_time (30s)
#t = datetime.datetime.now() - t0 / X

# totp = hotp(master_key, t)

def generate_master_key(master_key: str):
    try:
        with open(master_key_file, "w") as f:
            os.chmod(master_key_file, stat.S_IRWXU)
            print("original text:", master_key)
            key = Fernet.generate_key()
            fernet = Fernet(key)
            encrypted_key = fernet.encrypt(master_key.encode())
            print("Fernet key: ", key.decode("utf-8"))
            f.write(encrypted_key.decode("utf-8"))
            print("Successfully stored new master key!")
    except IOError as error:
        print(error)
    print("Generate master key")


def generate_ephemeral_key():
    try:
        # Get master key
        with open(master_key_file, "r") as f:
            encrypted_key = f.read()
            password = input("Enter password:")
            fernet = Fernet(bytes(password, "utf-8"))
            master_key = fernet.decrypt(bytes(encrypted_key, "utf-8")).decode()
            print(f"Hex secret: {master_key}")
#        print(f"Digits: {digits}")

        # Step 1: Generate an HMAC-SHA-256 value
        t0 = 0
        X = 30
        print(f"Step size (seconds): {X}")
        now = datetime.now(timezone.utc).replace(microsecond=0)
        start_time = datetime.fromtimestamp(0)
        print(f"Start time: {start_time} ({int(start_time.timestamp())})")
        print(f"Current time: {now} ({int(now.timestamp())})")
#        t = floor(( int(now.timestamp()) - int(start_time.timestamp())) / X) # use floor() ? 
        t = floor( (1111111109 / 30)) # use floor() ? 
        print(f"Counter: {hex(t).upper()} ({t})")
#        hash = hmac.new(bytes(master_key, "utf-8"), msg=bytes(str(t), "utf-8"), digestmod=hashlib.sha256)
        hash = hmac.new(bytes("12345678901234567890", "utf-8"), msg=t.to_bytes(8, 'big'), digestmod=hashlib.sha1)

        print(hash.hexdigest())
        hmac_hash = bytearray(hash.digest())

        offset = hmac_hash[-1] & 0xF

        code = (
            (hmac_hash[offset] & 0x7F) << 24
            | (hmac_hash[offset + 1] & 0xFF) << 16
            | (hmac_hash[offset + 2] & 0xFF) << 8
            | (hmac_hash[offset + 3] & 0xFF)
        )
        print(code)
        #str_code = str(code % 10**6))
        #print(str_code)
        #print(str_code[-6 :])

        # Step 2: Generate a 4-byte string (Dynamic Truncation)

        # Step 3: Compute an HOTP value
        # snum = string to num
        # return snum % 10%(len(str(snum)))

    except IOError as error:
        print(error)


def master_key_format(key: str) -> str:
    try:
        n = int(key, 16)
        keylen = len(key)
        if keylen == 64:
            return key
        raise argparse.ArgumentTypeError(
            f"Must be a 64 character hexadecimal. Actual len: {keylen}"
        )
    except ValueError:
        raise argparse.ArgumentTypeError(f"Argument {key} must be hexadecimal")


def generate():
    parser = argparse.ArgumentParser(
        description="Generates time-based ephemeral passwords based on a master key following the RFC 6283",
        epilog="Developed by louisabricot",
    )

    group = parser.add_mutually_exclusive_group()

    group.add_argument(
        "--master-key",
        "-m",
        type=master_key_format,
        help="generate the master key from the 64-character hexadecimal value",
    )
    group.add_argument(
        "--key",
        "-k",
        action="store_true",
        help="generate a time-based ephemeral password from the master key",
    )

    args = parser.parse_args()

    logging.basicConfig(filename="otp.log", level=logging.ERROR)

    if args.master_key is not None:
        generate_master_key(args.master_key)
    elif args.key is True:
        # TODO: check there is a key file with correct permission etc
        generate_ephemeral_key()
    else:
        parser.print_help(sys.stderr)
