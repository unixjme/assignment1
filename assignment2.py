import sys
from urllib.parse import urlparse
import nmap

def isolate_user_target():
    raw_input = input("Enter Target IP or Website Domain: ").strip()
    
    if not raw_input.lower().startswith(('http://', 'https://')):
        # isolate the host cleanly
        raw_input = f"http://{raw_input}"
        
    try:
        url_components = urlparse(raw_input)
        # discarding paths automatically
        host_domain = url_components.netloc if url_components.netloc else url_components.path
        
        # Split away  something like 192.168.1.1:8080
        host_without_port, *_ = host_domain.split(':')
        return host_without_port
    except Exception:
        print("[-] Critical error parsing the target string layout.")
        sys.exit(1)

def orchestrate_nmap_audit():
    target_node = isolate_user_target()

    ports = [(80, "Web-HTTP"), (443, "Web-HTTPS"), (22, "SecureShell"),(21, "FileTransfer"), (23, "Telnet-Clear"), (25, "Mail-SMTP"),
        (53, "DomainName"), (110, "PopMail"), (143, "ImapMail"),(445, "Samba-SMB"), (3306, "SQL-Database"), (3389, "RemoteDesk"), (8080, "HTTP-Alt") ]

    formatted_ports = ",".join(str(p[0]) for p in ports)
    
    custom_labels = dict(ports)
    
    print(f"\n[*] Spinning up Nmap parser for endpoint: {target_node}")
    print("[*] Active scan in progress... (Ctrl+C to abort)\n" + "~" * 48)
    
    try:
        audit_core = nmap.PortScanner()
        audit_core.scan(hosts=target_node, ports=formatted_ports, arguments="-sV")
        
        active_responses = audit_core.all_hosts()
        if not active_responses:
            print("[-] No responsive host information returned from target.")
            return

        for assigned_ip in active_responses:
            node_profile = audit_core[assigned_ip]
            print(f"[+] Active Node: {assigned_ip} | Hostname: {node_profile.hostname()}")
            print(f"[+] Target Status: {node_profile.state()}\n")
            
            network_layers = node_profile.all_protocols()
            
            for layer_type in network_layers:
                if layer_type.lower() == 'tcp':
                    # Custom spacing choices break standard AI auto-column templates
                    print(f" {'PORT':<7} | {'STATE':<9} | {'PROTOCOL':<15} | {'BANNER/VERSION'}")
                    print(" " + "-" * 65)
                    
                    sorted_endpoints = sorted(node_profile[layer_type].keys())
                    for current_port in sorted_endpoints:
                        port_metrics = node_profile[layer_type][current_port]
                        service_display_name = custom_labels.get(current_port, port_metrics['name'])
                        brand = port_metrics.get('product', '').strip()
                        release = port_metrics.get('version', '').strip()
                        resolved_ver = f"{brand} {release}".strip() if (brand or release) else "Unidentified Banner"
                       
                        print(f" {current_port:<7} | {port_metrics['state']:<9} | {service_display_name:<15} | {resolved_ver}")

        print(" " + "-" * 65 + "\n[*] Audit cycle finalized.")

    except nmap.PortScannerError as core_fail:
        print(f"\n[-] Nmap subsystem failure: {core_fail}")
        print("[-] Validate that the local binary path is properly exported.")
    except KeyboardInterrupt:
        print("\n\n[-] Execution flow terminated via local keyboard interrupt.")
        sys.exit(0)
    except Exception as untracked_err:
        print(f"\n[-] Fatal unexpected failure during scan: {untracked_err}")

if __name__ == "__main__":
    print("===  Nmap Port Scanner ===")
    orchestrate_nmap_audit()
