import argparse
import logging
import sys
import os
import stat
from cryptography.fernet import Fernet, InvalidToken
import hashlib
from datetime import datetime, timezone
import hmac
from math import floor
import base64

master_key_file = "ft_otp.key"

def generate_master_key(verbose: bool, master_key: str) -> None:
    """
    """

    try:
        with open(master_key_file, "w") as f:
            os.chmod(master_key_file, stat.S_IRUSR | stat.S_IWUSR)
            
            # Generate cypher key 
            key = Fernet.generate_key()
            print("Fernet key: ", key.decode("utf-8"))

            fernet = Fernet(key)
            encrypted_key = fernet.encrypt(master_key.encode())
            print(encrypted_key)

            # Store encrypted key into file
            f.write(encrypted_key.decode("utf-8"))

            print("Successfully stored new master key!")
    except IOError as error:
        logging.error(error)

def decrypt(encrypted: str) -> str:
    """
    """
    try:
        password = input("Enter password:")
        fernet = Fernet(bytes(password, 'utf-8'))
        # TODO: tester avec un encrypted_file vide
        # TODO: checker les valeurs de retour de Fernet
        decrypted = fernet.decrypt(bytes(encrypted, 'utf-8')).decode()
        return decrypted
    except InvalidToken as e:
        logging.error(f"Fernet raised an Invalid Token error: could not decrypt the master key")
        sys.exit(-1)


def generate_counter(start_time: int, current_time: int, interval_in_sec: int) -> int:
    return floor((current_time - start_time) / interval_in_sec)

def generate_hmac(key: str, start_time: int, current_time: int, counter: int, mode: str) -> str:
    return hmac.new(bytes(key, 'utf-8'), msg=counter.to_bytes(8, 'big'), digestmod=hashlib.sha1)

def truncate(hashByteArray: bytearray) -> bytearray:
    offset = hashByteArray[-1] & 0xF
    print(f"offset: {offset}")
    code = (
        (hashByteArray[offset] & 0x7F) << 24
        | (hashByteArray[offset + 1] & 0xFF) << 16
        | (hashByteArray[offset + 2] & 0xFF) << 8
        | (hashByteArray[offset + 3] & 0xFF)
    )
    return code

def compute_totp(code: bytearray, digits: int) -> str:
    str_code = str(10_000_000_000_000_000_000_000_000 + (code % 10**digits))
    return str_code[-digits :]

def generate_ephemeral_key(verbose: bool, digits: int):
    """
    """
    try:
        # Get master key
        with open(master_key_file, "r") as encrypted_file:
            decrypted_key = decrypt(encrypted_file.read())
            if not decrypted_key:
                logging.error("Could not decrypt master key")

        # Step 1: Generate an HMAC-SHA-256 value
        time_step = 30
        start_time = datetime.fromtimestamp(0)
        current_time = datetime.now(timezone.utc).replace(microsecond=0)
        # counter = floor(( int(now.timestamp()) - int(start_time.timestamp())) / interval_in_sec)  
        counter = generate_counter(int(start_time.timestamp()), int(current_time.timestamp()), time_step)

        hash = hmac.new(bytes(decrypted_key, 'utf-8'), msg=counter.to_bytes(8, 'big'), digestmod=hashlib.sha1)

        # master key
        # start time
        # current time
        if verbose:
            print(f"Hex secret: {decrypted_key}")
            print(f"Digits: {digits}")
            print(f"Step size (seconds): {interval_in_sec}")
            print(f"Start time: {start_time} ({int(start_time.timestamp())})")
            print(f"Current time: {now} ({int(current_time.timestamp())})")
            print(f"Counter: {hex(counter).upper()} ({counter})")

        # Step 2: Generate a 4-byte string (Dynamic Truncation)

        hashByteArray = bytearray(hash.digest())
        print(f"should be 20-byte string {len(hashByteArray)}")

        code = truncate(hashByteArray)
        # Step 3: Compute a HOTP value 
        
        totp = compute_totp(code, digits)
        
        return totp

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

    group.add_argument(
        "--digits",
        "-d",
        type=int,
        choices=range(6, 10),
        default=6,
        help="the length of the TOTP password",
    )

    group.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="display steps",
    )

    args = parser.parse_args()

    logging.basicConfig(filename="otp.log", level=logging.ERROR)

    if args.master_key is not None:
        generate_master_key(args.verbose, args.master_key)
    elif args.key is True:
        # TODO: check there is a key file with correct permission etc
        generate_ephemeral_key(args.verbose, args.digits)
    else:
        parser.print_help(sys.stderr)
