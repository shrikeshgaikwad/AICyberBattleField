#!/usr/bin/env python3
import socket
import struct
import sys

def check_eternalblue(target_ip, port=445):
    """
    Check if target is vulnerable to EternalBlue (MS17-010)
    Based on SMB protocol negotiation and vulnerability fingerprinting
    """
    print(f"[*] Testing {target_ip}:445 for EternalBlue (MS17-010)...")
    
    try:
        # SMB Negotiation packet
        negotiate_protocol_request = (
            b"\x00\x00\x00\x85"  # NetBIOS Session
            b"\xff\x53\x4d\x42"  # SMB1 Header
            b"\x72\x00\x00\x00"  # SMB_COM_NEGOTIATE
            b"\x00\x18\x53\xc8"
            b"\x00\x26"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\xff\xfe"
            b"\x00\x00\x00\x00\x00\x62\x00\x02"
            b"\x50\x43\x20\x4e\x45\x54\x57\x4f"
            b"\x52\x4b\x20\x50\x52\x4f\x47\x52"
            b"\x41\x4d\x20\x31\x2e\x30\x00\x02"
            b"\x4c\x41\x4e\x4d\x41\x4e\x31\x2e"
            b"\x30\x00\x02\x57\x69\x6e\x64\x6f"
            b"\x77\x73\x20\x66\x6f\x72\x20\x57"
            b"\x6f\x72\x6b\x67\x72\x6f\x75\x70"
            b"\x73\x20\x33\x2e\x31\x61\x00\x02"
            b"\x4c\x4d\x31\x2e\x32\x58\x30\x30"
            b"\x32\x00\x02\x4c\x41\x4e\x4d\x41"
            b"\x4e\x32\x2e\x31\x00\x02\x4e\x54"
            b"\x20\x4c\x4d\x20\x30\x2e\x31\x32"
            b"\x00"
        )
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((target_ip, port))
        sock.send(negotiate_protocol_request)
        
        response = sock.recv(1024)
        
        # Check SMB response
        if len(response) > 36:
            smb_header = response[4:8]
            if smb_header == b'\xff\x53\x4d\x42':
                print(f"[+] SMB1 protocol supported")
                
                # Try to detect vulnerable signature
                # EternalBlue exploits SMB1 in unpatched Windows systems
                session_setup = (
                    b"\x00\x00\x00\x48"
                    b"\xff\x53\x4d\x42\x73\x00\x00\x00\x00"
                    b"\x18\x07\xc8\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\xff\xfe\x00"
                    b"\x00\x40\x00\x0c\xff\x00\x48\x00\x04"
                    b"\x11\x0a\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x4e\x00\x00\x00\x00\x00"
                    b"\x00\x00\x57\x00\x69\x00\x6e\x00\x64"
                    b"\x00\x6f\x00\x77\x00\x73\x00\x20\x00"
                    b"\x32\x00\x30\x00\x30\x00\x30\x00\x20"
                    b"\x00\x32\x00\x31\x00\x39\x00\x35\x00"
                    b"\x00\x00\x57\x00\x69\x00\x6e\x00\x64"
                    b"\x00\x6f\x00\x77\x00\x73\x00\x20\x00"
                    b"\x32\x00\x30\x00\x30\x00\x30\x00\x20"
                    b"\x00\x35\x00\x2e\x00\x30\x00\x00\x00"
                )
                
                sock.send(session_setup)
                session_response = sock.recv(1024)
                
                if len(session_response) > 0:
                    print(f"[+] SMB session established - Target may be vulnerable")
                    print(f"[!] VULNERABLE: EternalBlue (MS17-010) likely exploitable")
                    sock.close()
                    return True
        
        sock.close()
        print(f"[-] Target appears patched or SMB1 disabled")
        return False
        
    except socket.timeout:
        print(f"[-] Connection timeout - SMB service may be filtered")
        return False
    except Exception as e:
        print(f"[-] Error: {str(e)}")
        return False

def enumerate_smb_shares(target_ip):
    """
    Attempt null session enumeration of SMB shares
    """
    print(f"\n[*] Attempting SMB share enumeration via null session...")
    try:
        import subprocess
        # Try net view command
        result = subprocess.run(
            ['net', 'view', f'\\\\{target_ip}', '/all'],
            capture_output=True, text=True, timeout=15
        )
        
        if result.returncode == 0 and result.stdout:
            print(f"[+] SMB shares discovered:")
            print(result.stdout)
            return result.stdout
        else:
            print(f"[-] No shares accessible or authentication required")
            if result.stderr:
                print(f"    Error: {result.stderr.strip()}")
    except Exception as e:
        print(f"[-] Share enumeration failed: {str(e)}")
    
    return None

if __name__ == "__main__":
    target = "192.168.0.3"
    
    # Check for EternalBlue
    is_vulnerable = check_eternalblue(target)
    
    # Enumerate shares
    enumerate_smb_shares(target)
    
    print("\n[*] SMB enumeration complete")
