"""Mass scan utilities for multiple targets."""
import re
import urllib.parse
from typing import List, Tuple, Dict


def parse_target_list(targets_text: str) -> List[Tuple[str, str]]:
    """
    Parse list of targets from text input with duplicate removal.
    Handles various formats:
    - https://domain.com/path/path (default port 443 ssl)
    - http://100.202.11.22:4000/path (custom port)
    - http://100.22.321.22/path (default port 80)
    - https://1002.333.221.11/path (default port 443 ssl)
    
    Deduplication rules:
    - www and non-www are treated as same domain
    - If same domain with different protocols, prefer https over http
    
    Returns:
        List of tuples (normalized_base_url, original_input)
        Paths are removed, default ports are handled, duplicates removed
    """
    lines = targets_text.strip().split('\n')
    parsed_targets = []
    
    # First pass: parse all URLs
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        original = line
        
        # Normalize URL
        base_url = normalize_target_url(line)
        if base_url:
            parsed_targets.append((base_url, original))
    
    # Second pass: deduplicate
    # Key: (hostname_without_www, port) -> (scheme, normalized_url, original)
    domain_map: Dict[Tuple[str, int], Tuple[str, str, str]] = {}
    
    for base_url, original in parsed_targets:
        try:
            parsed = urllib.parse.urlparse(base_url)
            scheme = parsed.scheme.lower()
            hostname = parsed.hostname
            port = parsed.port
            
            if not hostname:
                continue
            
            # Remove www. prefix for comparison
            hostname_normalized = hostname.lower()
            if hostname_normalized.startswith('www.'):
                hostname_normalized = hostname_normalized[4:]
            
            # Handle default ports
            if port is None:
                if scheme == 'https':
                    port = 443
                else:
                    port = 80
            
            # Key for deduplication: (hostname_without_www, port)
            key = (hostname_normalized, port)
            
            # If domain already exists, prefer https over http
            if key in domain_map:
                existing_scheme, existing_url, existing_original = domain_map[key]
                # Prefer https over http
                if scheme == 'https' and existing_scheme == 'http':
                    # Replace with https version, keep current hostname format
                    domain_map[key] = (scheme, base_url, original)
                # If both are same protocol or existing is https, keep existing
                # (don't replace)
            else:
                # New domain, add it
                domain_map[key] = (scheme, base_url, original)
        except Exception:
            # Invalid URL, skip it
            continue
    
    # Convert back to list of tuples
    result = [(url, original) for _, url, original in domain_map.values()]
    
    return result


def normalize_target_url(url: str) -> str:
    """
    Normalize target URL:
    - Remove paths
    - Handle default ports
    - Ensure protocol is present
    
    Args:
        url: Input URL string
        
    Returns:
        Normalized base URL without path, or empty string if invalid
    """
    url = url.strip()
    if not url:
        return ""
    
    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        # Try to detect if it should be https or http
        # If it looks like IP or domain without protocol, default to http
        url = 'http://' + url
    
    try:
        parsed = urllib.parse.urlparse(url)
        
        # Get scheme and hostname
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname
        
        if not hostname:
            return ""
        
        # Handle port
        port = parsed.port
        if port is None:
            # Default ports based on scheme
            if scheme == 'https':
                # For https, don't add port if it's default 443
                normalized = f"{scheme}://{hostname}"
            else:
                # For http, don't add port if it's default 80
                normalized = f"{scheme}://{hostname}"
        else:
            # Custom port specified
            normalized = f"{scheme}://{hostname}:{port}"
        
        return normalized
        
    except Exception:
        # Invalid URL, skip it
        return ""

