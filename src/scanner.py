import argparse
import nmap
from exporter import export_to_json
from rich.console import Console
from rich.table import Table

console = Console()

parser = argparse.ArgumentParser(description="Advanced Python Network Scanner")

parser.add_argument("-t", "--target", help="Target IP or Network", required=True)
parser.add_argument("-p", "--ports", help="Port range", default="1-1024")

args = parser.parse_args()

scanner = nmap.PortScanner()

results = {}

console.print(f"\n[bold cyan]Scanning {args.target} on ports {args.ports}...[/bold cyan]\n")

scanner.scan(hosts=args.target, ports=args.ports, arguments='-O')

for host in scanner.all_hosts():

    console.print(f"[bold green]Host:[/bold green] {host}")

    results[host] = {
        "os": "unknown",
        "ports": []
    }

    # OS Detection
    if 'osmatch' in scanner[host] and len(scanner[host]['osmatch']) > 0:
        os_name = scanner[host]['osmatch'][0]['name']
        console.print(f"[yellow]OS Detected:[/yellow] {os_name}")
        results[host]["os"] = os_name

    table = Table(title=f"Open Ports for {host}")

    table.add_column("Port", style="cyan")
    table.add_column("State", style="green")

    for proto in scanner[host].all_protocols():

        ports = scanner[host][proto].keys()

        for port in ports:

            state = scanner[host][proto][port]['state']

            if state == "open":

                table.add_row(str(port), state)

                results[host]["ports"].append(port)

    console.print(table)

console.print("[bold green]\nScan finished.[/bold green]")

export_to_json(results)