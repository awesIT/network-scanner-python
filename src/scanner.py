import argparse
import nmap

# créer le parser
parser = argparse.ArgumentParser(description="Python Network Scanner")

# arguments
parser.add_argument("-t", "--target", help="Target IP address", required=True)
parser.add_argument("-p", "--ports", help="Port range", default="1-1024")

args = parser.parse_args()

scanner = nmap.PortScanner()

print(f"Scanning {args.target} on ports {args.ports}...")

scanner.scan(args.target, args.ports)

for host in scanner.all_hosts():

    print("\nHost:", host)

    for proto in scanner[host].all_protocols():

        ports = scanner[host][proto].keys()

        for port in ports:

            state = scanner[host][proto][port]['state']

            print(f"Port {port}: {state}")