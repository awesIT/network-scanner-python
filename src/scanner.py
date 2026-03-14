import argparse
import nmap
from exporter import export_to_json

# CLI arguments
parser = argparse.ArgumentParser(description="Advanced Python Network Scanner")

parser.add_argument("-t", "--target", help="Target IP or Network (ex: 192.168.1.0/24)", required=True)
parser.add_argument("-p", "--ports", help="Port range", default="1-1024")

args = parser.parse_args()

# Initialize scanner
scanner = nmap.PortScanner()

# Dictionary to store results
results = {}

print(f"\nScanning network {args.target} on ports {args.ports}...\n")

# Scan network
scanner.scan(hosts=args.target, ports=args.ports, arguments='-O')

# Loop through hosts
for host in scanner.all_hosts():

    print("====================================")
    print("Host:", host)
    print("Status:", scanner[host].state())

    # Initialize host results
    results[host] = {
        "os": "unknown",
        "ports": []
    }

    # MAC Address
    if 'addresses' in scanner[host]:
        if 'mac' in scanner[host]['addresses']:
            mac = scanner[host]['addresses']['mac']
            print("MAC Address:", mac)

            if 'vendor' in scanner[host] and mac in scanner[host]['vendor']:
                vendor = scanner[host]['vendor'][mac]
                print("Vendor:", vendor)

    # OS detection
    if 'osmatch' in scanner[host]:
        if len(scanner[host]['osmatch']) > 0:
            os_name = scanner[host]['osmatch'][0]['name']
            print("OS Detected:", os_name)
            results[host]["os"] = os_name

    print("\nOpen Ports:")

    # Scan ports
    for proto in scanner[host].all_protocols():

        ports = scanner[host][proto].keys()

        for port in ports:

            state = scanner[host][proto][port]['state']

            if state == "open":
                print(f"Port {port}: {state}")
                results[host]["ports"].append(port)

print("\nScan finished.")

# Export results
export_to_json(results)