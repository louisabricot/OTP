from datetime import datetime
import hashlib
from otp import generate_counter

secret = "12345678901234567890"
secretInHex = secret.encode("utf-8").hex()
start_time = datetime.fromtimestamp(0)
time_step = 30


def test_counter_1():
    time = 59
    current_time = datetime.fromtimestamp(time)
    counter = generate_counter(
        int(start_time.timestamp()), int(current_time.timestamp()), time_step
    )
    assert hex(counter) == hex(1)


def test_counter_2():
    time = 1111111109
    current_time = datetime.fromtimestamp(time)

    counter = generate_counter(
        int(start_time.timestamp()), int(current_time.timestamp()), time_step
    )

    assert hex(counter).upper() == "0X23523EC"


def test_counter_3():
    time = 1111111111
    current_time = datetime.fromtimestamp(time)

    counter = generate_counter(
        int(start_time.timestamp()), int(current_time.timestamp()), time_step
    )

    assert hex(counter).upper() == "0X23523ED"


def test_counter_4():
    time = 1234567890
    current_time = datetime.fromtimestamp(time)

    counter = generate_counter(
        int(start_time.timestamp()), int(current_time.timestamp()), time_step
    )

    assert hex(counter).upper() == "0X273EF07"


def test_counter_5():
    time = 2000000000
    current_time = datetime.fromtimestamp(time)

    counter = generate_counter(
        int(start_time.timestamp()), int(current_time.timestamp()), time_step
    )

    assert hex(counter).upper() == "0X3F940AA"


def test_counter_6():
    time = 20000000000
    current_time = datetime.fromtimestamp(time)

    counter = generate_counter(
        int(start_time.timestamp()), int(current_time.timestamp()), time_step
    )

    assert hex(counter).upper() == "0X27BC86AA"
