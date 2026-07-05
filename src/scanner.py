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

# Ports connus pour présenter un risque de sécurité particulier s'ils sont exposés
RISKY_PORTS = {
    21: "FTP — souvent non chiffré, identifiants en clair",
    23: "Telnet — non chiffré, à désactiver",
    25: "SMTP — peut être utilisé pour du relais non autorisé",
    135: "MS-RPC — surface d'attaque connue sur Windows",
    139: "NetBIOS — expose des informations réseau",
    445: "SMB — cible fréquente de ransomwares (ex. EternalBlue)",
    3389: "RDP — souvent ciblé par brute force",
    5900: "VNC — accès distant parfois sans authentification forte",
}

console.print(f"\n[bold cyan]Scanning {args.target} on ports {args.ports}...[/bold cyan]\n")

# discover hosts
scanner.scan(hosts=args.target, arguments='-sn')
hosts = scanner.all_hosts()


def flag_risks(ports):
    """Retourne la liste des ports ouverts jugés sensibles, avec leur explication."""
    return [{"port": p, "risk": RISKY_PORTS[p]} for p in ports if p in RISKY_PORTS]


def scan_host(host):
    try:
        local_scanner = nmap.PortScanner()
        local_scanner.scan(hosts=host, ports=args.ports, arguments='-O')

        host_result = {
            "os": "unknown",
            "ports": [],
            "risks": []
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

        host_result["risks"] = flag_risks(host_result["ports"])
        if host_result["risks"]:
            console.print(f"[bold red]⚠ Ports à risque détectés sur {host} :[/bold red]")
            for r in host_result["risks"]:
                console.print(f"   [red]Port {r['port']}[/red] — {r['risk']}")

        console.print(table)
        return host, host_result

    except Exception as e:
        console.print(f"[bold red]Erreur lors du scan de {host} : {e}[/bold red]")
        return host, {"os": "error", "ports": [], "risks": [], "error": str(e)}


with ThreadPoolExecutor(max_workers=10) as executor:
    futures = []
    for host in hosts:
        futures.append(executor.submit(scan_host, host))
    for future in futures:
        host, data = future.result()
        results[host] = data

console.print("[bold green]\nScan finished.[/bold green]")
export_to_json(results)

