# hash_and_verify.py
# Demonstration of secure password hashing using Argon2 and bcrypt.
# This is a defensive example only.

import bcrypt
from argon2 import PasswordHasher

# ----------------------------------------------------------
# bcrypt hashing example
# ----------------------------------------------------------
def bcrypt_hash(password: str) -> bytes:
    """Generate a bcrypt hash for a given password."""
    salt = bcrypt.gensalt(rounds=12)  # 12 rounds is a good balance for demo
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed


def bcrypt_verify(password: str, hashed: bytes) -> bool:
    """Check if a plain password matches the bcrypt hash."""
    return bcrypt.checkpw(password.encode(), hashed)


# ----------------------------------------------------------
# Argon2 hashing example 
# ----------------------------------------------------------
# Configure Argon2 parameters: slightly heavy for security but fine for demo
ph = PasswordHasher(time_cost=2, memory_cost=102400, parallelism=8)


def argon2_hash(password: str) -> str:
    """Generate an Argon2 hash for a given password."""
    return ph.hash(password)


def argon2_verify(password: str, hashed: str) -> bool:
    """Verify a password against an Argon2 hash."""
    try:
        return ph.verify(hashed, password)
    except Exception:
        return False


# ----------------------------------------------------------
# Simple test run for demonstration purposes
# ----------------------------------------------------------
if __name__ == "__main__":
    # Sample password for testing
    pw = "security#@3200126678"
    print("Plain password:", pw)
    print("\n--- bcrypt demo ---")

    b_h = bcrypt_hash(pw)
    print("bcrypt hash:", b_h)
    print("bcrypt verify:", bcrypt_verify(pw, b_h))

    print("\n--- Argon2 demo ---")
    a_h = argon2_hash(pw)
    print("argon2 hash:", a_h)
    print("argon2 verify:", argon2_verify(pw, a_h))

    print("\n Both bcrypt and Argon2 successfully hashed and verified the password!")
