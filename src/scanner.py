import argparse
import nmap
from exporter import export_to_json
from rich.console import Console
from rich.table import Table
from concurrent.futures import ThreadPoolExecutor

console = Console()

parser = argparse.ArgumentParser(description="Advanced Python Network Scanner")

parser.add_argument("-t", "--target", help="Target Network", required=True)
parser.add_argument("-p", "--ports", help="Port range", default="1-1024")

args = parser.parse_args()

scanner = nmap.PortScanner()

results = {}

console.print(f"\n[bold cyan]Scanning {args.target} on ports {args.ports}...[/bold cyan]\n")

# discover hosts
scanner.scan(hosts=args.target, arguments='-sn')

hosts = scanner.all_hosts()

def scan_host(host):

    local_scanner = nmap.PortScanner()

    local_scanner.scan(hosts=host, ports=args.ports, arguments='-O')

    host_result = {
        "os": "unknown",
        "ports": []
    }

    console.print(f"[bold green]Host:[/bold green] {host}")

    if 'osmatch' in local_scanner[host] and len(local_scanner[host]['osmatch']) > 0:
        os_name = local_scanner[host]['osmatch'][0]['name']
        console.print(f"[yellow]OS Detected:[/yellow] {os_name}")
        host_result["os"] = os_name

    table = Table(title=f"Open Ports for {host}")

    table.add_column("Port")
    table.add_column("State")

    for proto in local_scanner[host].all_protocols():

        ports = local_scanner[host][proto].keys()

        for port in ports:

            state = local_scanner[host][proto][port]['state']

            if state == "open":

                table.add_row(str(port), state)

                host_result["ports"].append(port)

    console.print(table)

    return host, host_result


with ThreadPoolExecutor(max_workers=10) as executor:

    futures = []

    for host in hosts:
        futures.append(executor.submit(scan_host, host))

    for future in futures:
        host, data = future.result()
        results[host] = data


console.print("[bold green]\nScan finished.[/bold green]")

export_to_json(results)