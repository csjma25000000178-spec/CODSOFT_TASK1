
from scapy.all import sniff, IP, TCP, UDP, ICMP
import csv
import os
from datetime import datetime
from collections import Counter

CSV_FILE = "captured_packets.csv"
REPORT_FILE = "summary_report.txt"

counts = Counter()


def create_csv():
    if not os.path.exists(CSV_FILE) or os.path.getsize(CSV_FILE) == 0:
        with open(CSV_FILE, "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([
                "Timestamp", "Source IP",
                "Destination IP", "Protocol", "Packet Size"
            ])


def analyze_packet(packet):
    if IP not in packet:
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

    if TCP in packet:
        protocol = "TCP"
    elif UDP in packet:
        protocol = "UDP"
    elif ICMP in packet:
        protocol = "ICMP"
    else:
        protocol = "Other"

    packet_size = len(packet)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    counts["Total"] += 1
    counts[protocol] += 1

    print("\n--- Network Packet Details ---")
    print("Time           :", timestamp)
    print("Source IP      :", source_ip)
    print("Destination IP :", destination_ip)
    print("Protocol       :", protocol)
    print("Packet Size    :", packet_size, "bytes")

    with open(CSV_FILE, "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([
            timestamp, source_ip, destination_ip,
            protocol, packet_size
        ])

    print("Saved to CSV:", CSV_FILE)


def save_summary():
    report = [
        "NETWORK PACKET ANALYZER - SUMMARY REPORT",
        "=" * 42,
        f"Report generated: {datetime.now()}",
        f"Total packets: {counts['Total']}",
        f"TCP packets: {counts['TCP']}",
        f"UDP packets: {counts['UDP']}",
        f"ICMP packets: {counts['ICMP']}",
        f"Other IP packets: {counts['Other']}",
        "=" * 42
    ]

    with open(REPORT_FILE, "w") as file:
        file.write("\n".join(report) + "\n")

    print("\n" + "\n".join(report))
    print("\nSummary saved to:", os.path.abspath(REPORT_FILE))


def start_analyzer():
    create_csv()

    print("NETWORK PACKET ANALYZER")
    print("Packet data:", CSV_FILE)
    print("Summary report:", REPORT_FILE)
    print("Press Ctrl+C to stop capture.\n")

    try:
        sniff(prn=analyze_packet, store=False)
    except PermissionError:
        print("Permission denied. Try running as Administrator.")
    except KeyboardInterrupt:
        print("\nPacket capture stopped.")
    finally:
        save_summary()


if __name__ == "__main__":
    start_analyzer()
