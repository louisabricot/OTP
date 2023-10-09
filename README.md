# Time-Based Ephemeral Password Generator (TOTP)

This module provides functionality for generating time-based ephemeral passwords (TOTP) based on a master key following the RFC 6283 specification.

It includes functions for generating the master key, decrypting it, generating counters, truncating hash values, computing TOTP values, and generating ephemeral keys.

It includes functions for generating the master key, decrypting it, generating counters, truncating hash values, computing TOTP values, and generating ephemeral keys.
    
## Getting Started

### Requirements

To run this project, ensure you have:

    Python3
    Pip3
    Make

### Installation

1. Clone the repository:
```bash
  git clone https://github.com/louisabricot/OTP
  cd OTP
```

2. Install the required packages:
```bash
  make install
```

3. Setup the project:
```bash
  make
```

## Usage

The script can be run in two modes:

    Generate the master key from a 64-character hexadecimal value.
    Generate a time-based ephemeral password from the master key.
    
1. To generate the master key:

```bash
python script.py --master-key <64-character-hexadecimal-value>
```

2. To generate a time-based ephemeral password:

```bash
python script.py --key [-d <digits>] [-v]
```

Options

    --master-key, -m <64-character-hexadecimal-value>:
    Generate the master key from a 64-character hexadecimal value.

    --key, -k:
    Generate a time-based ephemeral password from the master key.

    --digits, -d <digits>:
    The length of the TOTP password (default is 6 digits).

    --verbose, -v:
    Display detailed steps while generating the password.

Example

Generate a master key:

```bash
python script.py --master-key 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
```

Generate a time-based ephemeral password:

```bash
python script.py --key -d 6 -v
```

### Running Tests

To run tests:

```bash
  make test
```

## Reference
[RFC6238](https://datatracker.ietf.org/doc/html/rfc6238)

