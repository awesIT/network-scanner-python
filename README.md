# 🔍 Python Network Scanner

![Python](https://img.shields.io/badge/Python-3.10-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/status-active-success)

A lightweight network reconnaissance tool written in Python. It discovers live hosts on a network, scans open ports, fingerprints the operating system, and exports results to JSON — with fast multithreaded scanning and clean colored terminal output.

## Screenshot

![Scanner](screenshots/Scan.png)

## Features

- 🌐 Network discovery — find live hosts on a subnet
- 🔓 Port scanning — detect open TCP ports per host
- 🖥️ OS detection — fingerprint the target operating system
- ⚡ Multithreaded scanning — fast results even on larger ranges
- 📄 JSON export — structured, machine-readable output
- 🎨 Colored terminal output (via `rich`) — clear, readable results

## Example output

```json
{
    "127.0.0.1": {
        "os": "Microsoft Windows 10 1809 - 21H2",
        "ports": [135, 445, 1001]
    }
}
```

## Project Structure

```
network-scanner-python/
│
├── src/
│   ├── scanner.py       # core scanning logic
│   └── exporter.py      # JSON export logic
│
├── screenshots/
├── requirements.txt
├── README.md
└── .gitignore
```

## Installation

```bash
git clone https://github.com/awesIT/network-scanner-python.git
cd network-scanner-python
pip install -r requirements.txt
```

> Note: this project uses `python-nmap`, which requires `nmap` to be installed on your system (`sudo apt install nmap` on Linux, or download from [nmap.org](https://nmap.org/download.html) for Windows/macOS).

## Usage

```bash
python src/scanner.py --target 192.168.1.0/24
```

Results are displayed in the terminal and exported to `scan_results.json`.

## Disclaimer

This tool is intended for educational purposes and authorized security testing only. Never scan a network you do not own or do not have explicit permission to test.

## Roadmap

- [ ] Basic vulnerability flagging (e.g. alert on known-risky open ports like Telnet/FTP)
- [ ] CVE lookup for detected service versions
- [ ] Unit tests
- [ ] CLI progress bar for large scans

## License

MIT
