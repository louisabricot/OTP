from datetime import datetime
import hashlib
from otp import generate_counter, truncate, compute_totp
import hmac

secret = "12345678901234567890"
secretInHex = secret.encode("utf-8").hex()
start_time = datetime.fromtimestamp(0)
time_step = 30
digits = 8
testTime = [59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000]
testMode = [hashlib.sha1, hashlib.sha256, hashlib.sha512]


def test_totp_0():
    counter = generate_counter(int(start_time.timestamp()), int(testTime[0]), time_step)
    counterToBytes = counter.to_bytes(8, "big")

    # SHA1
    hash = hmac.new(bytes(secret, "utf-8"), msg=counterToBytes, digestmod=hashlib.sha1)
    hashByteArray = bytearray(hash.digest())
    code = truncate(hashByteArray)
    totp = compute_totp(code, digits)
    assert totp == "94287082"


def test_totp_3():
    counter = generate_counter(int(start_time.timestamp()), int(testTime[1]), time_step)
    counterToBytes = counter.to_bytes(8, "big")

    # SHA1
    hash = hmac.new(bytes(secret, "utf-8"), msg=counterToBytes, digestmod=hashlib.sha1)
    hashByteArray = bytearray(hash.digest())
    code = truncate(hashByteArray)
    totp = compute_totp(code, digits)
    assert totp == "07081804"


def test_totp_6():
    counter = generate_counter(int(start_time.timestamp()), int(testTime[2]), time_step)
    counterToBytes = counter.to_bytes(8, "big")

    # SHA1
    hash = hmac.new(bytes(secret, "utf-8"), msg=counterToBytes, digestmod=hashlib.sha1)
    hashByteArray = bytearray(hash.digest())
    code = truncate(hashByteArray)
    totp = compute_totp(code, digits)
    assert totp == "14050471"


def test_totp_9():
    counter = generate_counter(int(start_time.timestamp()), int(testTime[3]), time_step)
    counterToBytes = counter.to_bytes(8, "big")

    # SHA1
    hash = hmac.new(bytes(secret, "utf-8"), msg=counterToBytes, digestmod=hashlib.sha1)
    hashByteArray = bytearray(hash.digest())
    code = truncate(hashByteArray)
    totp = compute_totp(code, digits)
    assert totp == "89005924"


def test_totp_12():
    counter = generate_counter(int(start_time.timestamp()), int(testTime[4]), time_step)
    counterToBytes = counter.to_bytes(8, "big")

    # SHA1
    hash = hmac.new(bytes(secret, "utf-8"), msg=counterToBytes, digestmod=hashlib.sha1)
    hashByteArray = bytearray(hash.digest())
    code = truncate(hashByteArray)
    totp = compute_totp(code, digits)
    assert totp == "69279037"


def test_totp_15():
    counter = generate_counter(int(start_time.timestamp()), int(testTime[5]), time_step)
    counterToBytes = counter.to_bytes(8, "big")

    # SHA1
    hash = hmac.new(bytes(secret, "utf-8"), msg=counterToBytes, digestmod=hashlib.sha1)
    hashByteArray = bytearray(hash.digest())
    code = truncate(hashByteArray)
    totp = compute_totp(code, digits)
    assert totp == "65353130"
