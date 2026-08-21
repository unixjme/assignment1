import socket
from sys import exit as terminate_process
from urllib.parse import urlparse

def isolate_network_node():
    raw_node = input("Enter Target IP or Domain: ").strip()
    if not raw_node.lower().startswith(('http://', 'https://')):
        raw_node = f"http://{raw_node}"
        
    try:
        url_map = urlparse(raw_node)
        endpoint = url_map.netloc if url_map.netloc else url_map.path
        
        host_only, *_ = endpoint.split(':')
        return host_only
    except Exception:
        print("[-] Error interpreting target string format.")
        terminate_process(1)

def run_network_check():
    target_host = isolate_network_node()
    print(f"[*] Analyzing network records for target: {target_host}")
    
    try:
        resolved_ip = socket.gethostbyname(target_host)
        print(f"[+] Operational IP Target: {resolved_ip}\n" + "~"*40)
    except socket.gaierror:
        print(f"[-] Subsystem failed to resolve reference '{target_host}'. Verify routing/spelling.")
        terminate_process(1)

    target_ports = [
        (80, "Web-HTTP"), (443, "Web-HTTPS"), (22, "SecureShell"),
        (21, "FileTransfer"), (23, "Telnet-Clear"), (25, "Mail-SMTP"),
        (53, "DomainName"), (110, "PopMail"), (143, "ImapMail"),
        (445, "Samba-SMB"), (3306, "SQL-Database"), (3389, "RemoteDesk"), (8080, "HTTP-Alt")
    ]

    try:
        for network_port, application_tag in target_ports:
            communication_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            communication_socket.settimeout(1.2)

            handshake_status = communication_socket.connect_ex((resolved_ip, network_port))
            
            if handshake_status == 0:
                print(f"[OPEN] Port {network_port:<5} running -> {application_tag}")
            else:
                print(f"[CLOSED] Port {network_port:<5} ({application_tag})")
                
            communication_socket.close()
            
    except KeyboardInterrupt:
        print("\n[-] Scan halted abruptly by user signal.")
        try:
            communication_socket.close()
        except NameError:
            pass

if __name__ == "__main__":
    print("--- Port Scanner Tool ---")
    run_network_check()
    print("~"*40 + "\n[*] Sequence fully executed.")
