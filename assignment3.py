import socket
from sys import exit as shut_down
from urllib.parse import urlparse

def clean_user_input():
    #Captures and cleanly isolates the target host from domains or full URLs.
    raw_target = input("Enter Target IP or Website Domain: ").strip()

    if not raw_target.lower().startswith(('http://', 'https://')):
        
        raw_target = f"http://{raw_target}"
        
    try:
        url_segments = urlparse(raw_target)
        # Pull out the primary network location block
        clean_host = url_segments.netloc if url_segments.netloc else url_segments.path
        
        # Split away a port if the user typed something like google.com:80
        host_without_port, *_ = clean_host.split(':')
        return host_without_port
    except Exception:
        print("[-] Problem processing input string format.")
        shut_down(1)

def translate_to_ip(node_name):
    #Performs a live DNS lookup if given a domain name, otherwise passes through the IP.
    try:
        print(f"[*] Resolving routing path details for: {node_name}")
        resolved_ip = socket.gethostbyname(node_name)
        return resolved_ip
    except socket.gaierror:
        print(f"[-] Network resolution error. Unable to locate target reference '{node_name}'.")
        shut_down(1)

def evaluate_subnet_tier(target_ip):
    try:
        first_segment, *_ = target_ip.split('.')
        octet_val = int(first_segment)
    except (ValueError, IndexError):
        return "Non-Standard Subnet Layout"

    class_ranges = [
        (range(1, 127), "Class A (Large Scale Enterprise)"),
        (range(127, 128), "Class A (Internal Loopback Frame)"),
        (range(128, 192), "Class B (Medium Scale Campus)"),
        (range(192, 224), "Class C (Small Localized Subnet)"),
        (range(224, 240), "Class D (Multicast Operations)"),
        (range(240, 256), "Class E (Research/Experimental Allocation)")
    ]

    for numeric_span, descriptive_tag in class_ranges:
        if octet_val in numeric_span:
            return descriptive_tag

    return "Outside Tracked IPv4 Ranges"

def execute_analysis_matrix():
    
    raw_host = clean_user_input() # Handle input validation

    active_ip = translate_to_ip(raw_host) #Normalize input to an actual IP address
    
    address_tier = evaluate_subnet_tier(active_ip) #Determine the class
    
    print("\n" + "~" * 50)
    print(f" Target IP or Website Domain : {raw_host}")
    print(f" Mapped IPv4    : {active_ip}")
    print(f" Structural Address Tier: {address_tier}")
    print("~" * 50 + "\n")

if __name__ == "__main__":
    print("--- Host Discovery Tool ---")
    try:
        execute_analysis_matrix()
        print("[+] Host Discovery Tool terminated successfully.")
    except KeyboardInterrupt:
        print("\n[-] Thread execution halted by console signal interrupt.")
        shut_down(0)
