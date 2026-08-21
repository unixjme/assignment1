#!/bin/bash

# Nmap scripts path on Linux /usr/share/nmap/scripts/
NSE_DIRECTORY="/usr/share/nmap/scripts"

# Emergency exit function if the user presses Ctrl+C
abort_scan() {
    echo -e "\n\n[-] Scan cancelled by user. Terminating process cleanly..."
    exit 130
}
trap abort_scan SIGINT

echo "=== Custom Nmap NSE Execution Tool ==="

# Grab target host details from the user
read -p "[?] Enter Target IP or Domain: " target_input
target=$(echo "$target_input" | tr -d ' ') # strip accidental whitespace

if [ -z "$target" ]; then
    echo "[-] Error: Target field cannot be blank."
    exit 1
fi

# Grab the script name from the user
read -p "[?] Enter NSE Script Name (e.g., http-enum): " script_name
script_name=$(echo "$script_name" | tr -d ' ')

if [ -z "$script_name" ]; then
    echo "[-] Error: NSE script selection required."
    exit 1
fi

# Append .nse extension automatically if the user forgot it
if [[ "$script_name" != *.nse ]]; then
    script_name="${script_name}.nse"
fi

# Validation checks before running
if ! command -v nmap &> /dev/null; then
    echo "[-] System Error: 'nmap' binary not found. Please install it on your OS first."
    exit 1
fi

# Check if the requested script exists in Nmap directory (Skipped if running a built-in category like 'vuln' or 'discovery')
if [[ ! "$script_name" =~ ^(default|vuln|discovery|safe|intrusive|auth|broadcast|malware)\.nse$ ]]; then
    if [ ! -f "${NSE_DIRECTORY}/${script_name}" ]; then
        echo "[!] Warning: Could not locate '${script_name}' in ${NSE_DIRECTORY}."
        echo "[*] Attempting execution anyway in case of custom or global path storage..."
    fi
fi

# Trigger the Nmap scan engine
echo -e "\n[*] Initializing engine parameters..."
echo "[*] Running: nmap --script=${script_name} ${target}"
echo -e "------------------------------------------------------------\n"

# Nmap naturally resolves both raw IPs and domains natively.
nmap --script="${script_name}" "${target}"

echo -e "\n------------------------------------------------------------"
echo "[+] Audit sequence completed successfully."
