"""Encoding utilities for WAF bypass."""
import json


def encode_unicode(data: bytes) -> bytes:
    """
    Encode string content in JSON to Unicode escape sequences for WAF bypass.
    Only encodes bytes inside string literals (between quotes).
    """
    result = bytearray()
    in_string = False
    i = 0
    
    while i < len(data):
        b = data[i]
        
        if b == ord('"'):
            in_string = not in_string
            result.append(b)
            i += 1
            continue
        
        if not in_string:
            result.append(b)
            i += 1
            continue
        
        # Handle escape sequences
        if b == ord('\\'):
            result.append(b)
            if i + 1 < len(data):
                result.append(data[i + 1])
                i += 2
            else:
                i += 1
            continue
        
        # Encode byte as Unicode escape
        escape = f"\\u{b:04x}".encode('ascii')
        result.extend(escape)
        i += 1
    
    return bytes(result)


def encode_utf16le(s: str) -> bytes:
    """
    Encode string as UTF-16LE.
    
    Args:
        s: String to encode
        
    Returns:
        UTF-16LE encoded bytes
    """
    return s.encode('utf-16-le')


def marshal_json(obj) -> bytes:
    """
    Marshal object to JSON without HTML escaping.
    
    Args:
        obj: Object to serialize
        
    Returns:
        JSON bytes without trailing newline
    """
    json_str = json.dumps(obj, ensure_ascii=False, separators=(',', ':'))
    json_bytes = json_str.encode('utf-8')
    # Remove trailing newline if present (json.dumps doesn't add one by default)
    return json_bytes.rstrip(b'\n')

