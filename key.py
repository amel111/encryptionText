import hashlib

def derive_key(password):
    """Hash password to derive a consistent key."""
    hashed = hashlib.sha256(password.encode()).digest()
    return hashed
