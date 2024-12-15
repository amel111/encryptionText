from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def encrypt(text, key):
    """Encrypt the text using the derived key."""
    iv = os.urandom(16)  # Initialization Vector (IV)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_text = encryptor.update(text.encode()) + encryptor.finalize()
    return iv + encrypted_text  # Gabungkan IV dengan teks terenkripsi

def decrypt(encrypted_text, key):
    """Decrypt the text using the derived key."""
    iv = encrypted_text[:16]  # Ekstrak IV dari awal data
    actual_encrypted_text = encrypted_text[16:]  # Sisanya adalah teks terenkripsi
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    try:
        decrypted_text = decryptor.update(actual_encrypted_text) + decryptor.finalize()
        return decrypted_text.decode()
    except Exception:
        # Jika dekripsi gagal, hasilkan teks acak
        return "ERROR: Invalid Password - Decoded Text is Random!"
