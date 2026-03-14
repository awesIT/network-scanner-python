import argparse
import nmap

# Création du parser CLI
parser = argparse.ArgumentParser(description="Python Network Scanner")

# Arguments
parser.add_argument("-t", "--target", help="Target IP address", required=True)
parser.add_argument("-p", "--ports", help="Port range", default="1-1024")

args = parser.parse_args()

# Initialiser le scanner Nmap
scanner = nmap.PortScanner()

print(f"Scanning {args.target} on ports {args.ports}...\n")

# Scan avec détection OS
scanner.scan(args.target, args.ports, arguments='-O')

# Parcourir les hosts trouvés
for host in scanner.all_hosts():

    print("================================")
    print("Host:", host)

    # Détection OS
    if 'osmatch' in scanner[host] and len(scanner[host]['osmatch']) > 0:
        os_name = scanner[host]['osmatch'][0]['name']
        print("OS Detected:", os_name)

    print("\nOpen Ports:")

    # Parcourir les protocoles
    for proto in scanner[host].all_protocols():

        ports = scanner[host][proto].keys()

        for port in ports:

            state = scanner[host][proto][port]['state']

            if state == "open":
                print(f"Port {port}: {state}")

print("\nScan finished.")