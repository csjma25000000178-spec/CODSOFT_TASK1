# NETWATCH — Network Packet Analyzer

A Python-based network packet analyzer with a graphical dashboard for monitoring network traffic in real time.

## Features

- Real-time packet capture using Scapy
- Dark theme with neon-green interface
- Displays source IP and destination IP
- Identifies TCP, UDP, ICMP, and other IP packets
- Shows total packets, protocol counts, and packet sizes
- Search packets and filter by protocol
- Export captured packet details to CSV
- Generate a packet summary report
- Clear the packet table and reset statistics

## Technologies Used

- Python
- Scapy
- Tkinter
- CSV file handling
- Git and GitHub

## Project Files

- `packet_analyzer.py` — command-line packet analyzer
- `dashboard.py` — graphical packet analyzer dashboard
- `requirements.txt` — Python dependency list

## Installation

1. Install Python 3 on your computer.
2. Install Npcap on Windows if required for packet capture.
3. Open a terminal in the project folder.
4. Install the required package:

```bash
python -m pip install -r requirements.txt
```

## Run the Dashboard

```bash
python dashboard.py
```

If packet capture does not start on Windows, check Npcap installation and the permissions required by your system.

## Run the Command-Line Analyzer

```bash
python packet_analyzer.py
```

## Important Note

Use this tool only on networks and devices you own or have explicit permission to monitor. Packet capture may expose sensitive network information. Do not publish captured traffic or private reports.

## Author

Created as a Python network monitoring project.
