"""
This module provides functionality for generating time-based ephemeral passwords (TOTP)
based on a master key following the RFC 6283 specification.

It includes functions for generating the master key, decrypting it, generating counters,
truncating hash values, computing TOTP values, and generating ephemeral keys.

The script can be run in two modes:
1. Generate the master key from a 64-character hexadecimal value.
2. Generate a time-based ephemeral password from the master key.

Usage:
    1. To generate the master key:
       $ python script.py --master-key <64-character-hexadecimal-value>

    2. To generate a time-based ephemeral password:
       $ python script.py --key [-d <digits>] [-v]

Options:
    --master-key, -m <64-character-hexadecimal-value>:
        Generate the master key from a 64-character hexadecimal value.

    --key, -k:
        Generate a time-based ephemeral password from the master key.

    --digits, -d <digits>:
        The length of the TOTP password (default is 6 digits).

    --verbose, -v:
        Display detailed steps while generating the password.

Example:
    Generate a master key:
    $ python script.py --master-key 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF

    Generate a time-based ephemeral password:
    $ python script.py --key -d 6 -v

Developed by louisabricot
"""

import argparse
import logging
import sys
import os
import stat
import hashlib
from datetime import datetime, timezone
import hmac
from math import floor
from cryptography.fernet import Fernet, InvalidToken

MASTER_KEY_FILE = "ft_otp.key"


def generate_master_key(master_key: str) -> None:
    """
    Generate and store a master key.

    This function generates a new master key, encrypts it using Fernet encryption
    with a provided master password, and stores it in the 'ft_otp.key' file.

    Args:
        master_key (str): A 64-character hexadecimal value.

    Returns:
        None
    """
    try:
        with open(MASTER_KEY_FILE, "w", encoding="utf-8") as file:
            os.chmod(MASTER_KEY_FILE, stat.S_IRUSR | stat.S_IWUSR)

            # Generate cypher key
            key = Fernet.generate_key()
            print("Fernet key: ", key.decode("utf-8"))

            fernet = Fernet(key)
            encrypted_key = fernet.encrypt(master_key.encode())

            # Store encrypted key into file
            file.write(encrypted_key.decode("utf-8"))

            print("Successfully stored new master key!")
    except IOError as error:
        logging.error(error)


def decrypt(encrypted: str) -> str:
    """
    Decrypt an encrypted string using a password.

    Args:
        encrypted (str): The encrypted string to decrypt.

    Returns:
        str: The decrypted string.

    Raises:
        InvalidToken: If decryption fails.
    """
    try:
        password = input("Enter password:")
        fernet = Fernet(bytes(password, "utf-8"))
        decrypted = fernet.decrypt(bytes(encrypted, "utf-8")).decode()
        return decrypted
    except InvalidToken:
        logging.error("Fernet raised an Invalid Token error")
        sys.exit(-1)


def generate_counter(start_time: int, current_time: int, time_step: int) -> int:
    """
    Generate a time-based counter value.

    Args:
        start_time (int): The starting time as a Unix timestamp.
        current_time (int): The current time as a Unix timestamp.
        time_step (int): The time step size in seconds.

    This function calculates the counter value based on the provided start time,
    current time, and time step size, following RFC 6283.

    Returns:
        int: The generated counter value.
    """
    return floor((current_time - start_time) / time_step)


def truncate(hash_byte_array: bytearray) -> bytearray:
    """
    Truncate a hash byte array to a 4-byte value.

    Args:
        hash_byte_array (bytearray): The hash byte array to truncate.

    This function performs dynamic truncation on the provided hash byte array,
    following RFC 6283, and returns a 4-byte truncated value.

    Returns:
        bytearray: The truncated hash value as a bytearray.
    """
    offset = hash_byte_array[-1] & 0xF
    code = (
        (hash_byte_array[offset] & 0x7F) << 24
        | (hash_byte_array[offset + 1] & 0xFF) << 16
        | (hash_byte_array[offset + 2] & 0xFF) << 8
        | (hash_byte_array[offset + 3] & 0xFF)
    )
    return code


def compute_totp(code: bytearray, digits: int) -> str:
    """
    Compute a TOTP value from a truncated code.

    Args:
        code (bytearray): The truncated code as a bytearray.
        digits (int): The length of the TOTP password.

    This function computes the TOTP value from the provided truncated code
    and returns it as a string with the specified number of digits.

    Returns:
        str: The computed TOTP value as a string.
    """
    str_code = str(10_000_000_000 + (code % 10**digits))
    return str_code[-digits:]


def generate_ephemeral_key(verbose: bool, digits: int):
    """
    Generate a time-based ephemeral password.

    Args:
        verbose (bool): Whether to display detailed steps.
        digits (int): The length of the TOTP password.

    This function generates a time-based ephemeral password based on the master key
    stored in 'ft_otp.key'. It follows the RFC 6283 specification and displays
    detailed steps if 'verbose' is True.

    Returns:
        None
    """
    try:
        # Get master key
        with open(MASTER_KEY_FILE, "r", encoding="utf-8") as encrypted_key:
            decrypted_key = decrypt(encrypted_key.read())
            if not decrypted_key:
                logging.error("Could not decrypt master key")

        # Step 1: Generate an HMAC-SHA-256 value
        time_step = 30
        start_time = datetime.fromtimestamp(0)
        current_time = datetime.now(timezone.utc).replace(microsecond=0)
        counter = generate_counter(
            int(start_time.timestamp()), int(current_time.timestamp()), time_step
        )

        hasher = hmac.new(
            bytes.fromhex(decrypted_key),
            msg=counter.to_bytes(8, "big"),
            digestmod=hashlib.sha1,
        )

        if verbose:
            print(f"Hex secret: {decrypted_key}")
            print(f"Digits: {digits}")
            # For now we only implement SHA1
            print("TOTP mode: SHA1")
            print(f"Step size (seconds): {time_step}")
            print(f"Start time: {start_time} ({int(start_time.timestamp())})")
            print(f"Current time: {current_time} ({int(current_time.timestamp())})")
            print(f"Counter: {hex(counter).upper()} ({counter})")

        # Step 2: Generate a 4-byte string (Dynamic Truncation)

        hash_byte_array = bytearray(hasher.digest())
        code = truncate(hash_byte_array)

        # Step 3: Compute a HOTP value

        totp = compute_totp(code, digits)
        print(f"TOTP: {totp}")

    except IOError as error:
        logging.error(error)


def master_key_format(key: str) -> str:
    """
    Validate and format a master key in hexadecimal format.

    Args:
        key (str): The master key as a 64-character hexadecimal value.

    This function checks whether the provided 'key' is a valid 64-character hexadecimal
    value. If valid, it returns the formatted key. Otherwise, it raises an
    'argparse.ArgumentTypeError' with an appropriate error message.

    Returns:
        str: The formatted 64-character hexadecimal master key.

    Raises:
        argparse.ArgumentTypeError: If the 'key' is not a valid 64-character hexadecimal.
    """
    try:
        # Check if key is valid hexadecimal
        int(key, 16)
        keylen = len(key)
        if keylen == 64:
            return key
        raise argparse.ArgumentTypeError(
            f"Must be a 64 character hexadecimal. Actual len: {keylen}"
        )
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Argument {key} must be hexadecimal") from exc


def main():
    """
    Parse command-line arguments and execute the appropriate action.

    Returns:
        None
    """
    parser = argparse.ArgumentParser(
        description="Generates time-based ephemeral passwords based on a master key",
        epilog="Developed by louisabricot",
    )

    actions = parser.add_mutually_exclusive_group()

    actions.add_argument(
        "--master-key",
        "-m",
        type=master_key_format,
        help="generate the master key from the 64-character hexadecimal value",
    )

    actions.add_argument(
        "--key",
        "-k",
        action="store_true",
        help="generate a time-based ephemeral password from the master key",
    )

    parser.add_argument(
        "--digits",
        "-d",
        required=False,
        type=int,
        choices=range(6, 11),
        default=6,
        help="the length of the TOTP password",
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="display steps",
    )

    args = parser.parse_args()

    logging.basicConfig(filename="otp.log", level=logging.ERROR)
    logging.getLogger().addHandler(logging.StreamHandler())

    if args.master_key is not None:
        if args.digits is not None:
            print("Ignoring option --digits")
        generate_master_key(args.master_key)
    elif args.key is True:
        generate_ephemeral_key(args.verbose, args.digits)
    else:
        parser.print_help(sys.stderr)
