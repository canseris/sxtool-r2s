"""Security utilities for target validation."""
import socket
import json
import sys
import urllib.parse
import urllib.request
from typing import Optional
import tkinter.messagebox as messagebox


def is_private_ip(ip_str: str) -> bool:
    """
    Check if IP address is private/local.
    
    Args:
        ip_str: IP address string
        
    Returns:
        True if private IP
    """
    try:
        ip = socket.inet_aton(ip_str)
        
        # Loopback
        if ip[0] == 127:
            return True
        
        # Private ranges
        # 10.0.0.0/8
        if ip[0] == 10:
            return True
        
        # 172.16.0.0/12
        if ip[0] == 172 and 16 <= ip[1] <= 31:
            return True
        
        # 192.168.0.0/16
        if ip[0] == 192 and ip[1] == 168:
            return True
        
        # Link-local
        if ip[0] == 169 and ip[1] == 254:
            return True
        
        return False
    except (socket.error, ValueError):
        return False


def check_security(target_url: str, parent_window=None) -> bool:
    """
    Check if target URL is safe to test (block sensitive domains/IPs).
    
    Args:
        target_url: Target URL to check
        parent_window: Optional tkinter window for dialogs
        
    Returns:
        True if safe, False if blocked
    """
    # Normalize URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    try:
        parsed = urllib.parse.urlparse(target_url)
        host = parsed.hostname
        if not host:
            return True
        
        host_lower = host.lower()
        
        # Check for sensitive domains
        if '.gov' in host_lower or '.edu' in host_lower:
            msg = f"Terdeteksi domain sensitif ({host})！\nKlik OK untuk keluar dari program."
            if parent_window:
                messagebox.showerror("Operasi dilarang", msg, parent=parent_window)
            sys.exit(0)
            return False
        
        # Resolve IP
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            return True
        
        # Allow private IPs
        if is_private_ip(ip):
            return True
        
        # Check geo-location via ip-api.com
        try:
            req = urllib.request.Request(
                f"http://ip-api.com/json/{ip}",
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            with urllib.request.urlopen(req, timeout=2) as response:
                data = json.loads(response.read().decode('utf-8'))
                country_code = data.get('countryCode', '')
                
                if country_code == 'CN':
                    msg = f"IP target ({ip}) berada di China (CN)。\nKlik OK untuk keluar dari program."
                    if parent_window:
                        messagebox.showerror("Operasi dilarang", msg, parent=parent_window)
                    sys.exit(0)
                    return False
        except Exception:
            # If geo-check fails, allow it
            pass
        
        return True
        
    except Exception:
        # If check fails, allow it
        return True

