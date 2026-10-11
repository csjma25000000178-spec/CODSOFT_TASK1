
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from scapy.all import sniff, IP, TCP, UDP, ICMP
from threading import Thread, Event, Lock
from datetime import datetime
import csv

# ---------- SETTINGS ----------
APP_TITLE = "NETWATCH | Network Packet Analyzer"
BG = "#050b08"
PANEL = "#0b1710"
GREEN = "#39ff14"
MUTED = "#83a889"
RED = "#ff6262"
YELLOW = "#ffd166"

stop_event = Event()
data_lock = Lock()
packet_rows = []

counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}
total_packets = 0
total_bytes = 0
capturing = False
capture_thread = None

# ---------- WINDOW ----------
root = tk.Tk()
root.title(APP_TITLE)
root.geometry("1200x780")
root.minsize(950, 620)
root.configure(bg=BG)

# ---------- HEADER ----------
header = tk.Frame(root, bg=BG)
header.pack(fill="x", padx=20, pady=(16, 5))

tk.Label(
    header, text=">>> NETWATCH",
    font=("Consolas", 25, "bold"),
    bg=BG, fg=GREEN
).pack(side="left")

tk.Label(
    header, text="// NETWORK SECURITY MONITOR",
    font=("Consolas", 11),
    bg=BG, fg=MUTED
).pack(side="left", padx=16, pady=(10, 0))

status_label = tk.Label(
    root, text="● SYSTEM READY",
    font=("Consolas", 11, "bold"),
    bg=BG, fg=GREEN
)
status_label.pack(anchor="w", padx=24, pady=5)

# ---------- STATISTICS ----------
stats_frame = tk.Frame(root, bg=BG)
stats_frame.pack(fill="x", padx=15, pady=12)


def create_stat(title):
    card = tk.Frame(
        stats_frame, bg=PANEL,
        highlightbackground="#1c4828",
        highlightthickness=1, padx=10, pady=10
    )
    card.pack(side="left", expand=True, fill="x", padx=4)

    tk.Label(
        card, text=title, bg=PANEL,
        fg=MUTED, font=("Consolas", 9, "bold")
    ).pack()

    value = tk.Label(
        card, text="0", bg=PANEL,
        fg=GREEN, font=("Consolas", 21, "bold")
    )
    value.pack(pady=(5, 0))
    return value


total_value = create_stat("TOTAL PACKETS")
tcp_value = create_stat("TCP")
udp_value = create_stat("UDP")
icmp_value = create_stat("ICMP")
bytes_value = create_stat("TOTAL BYTES")

# ---------- SEARCH AND FILTER ----------
toolbar = tk.Frame(root, bg=BG)
toolbar.pack(fill="x", padx=20, pady=(4, 10))

tk.Label(
    toolbar, text="SEARCH:",
    bg=BG, fg=GREEN, font=("Consolas", 10, "bold")
).pack(side="left", padx=(0, 8))

search_var = tk.StringVar()

search_entry = tk.Entry(
    toolbar, textvariable=search_var,
    bg="#101f14", fg=GREEN,
    insertbackground=GREEN,
    font=("Consolas", 11),
    relief="flat", width=24
)
search_entry.pack(side="left", ipady=7, padx=(0, 15))

tk.Label(
    toolbar, text="PROTOCOL:",
    bg=BG, fg=GREEN,
    font=("Consolas", 10, "bold")
).pack(side="left", padx=(0, 8))

protocol_var = tk.StringVar(value="ALL")

protocol_box = ttk.Combobox(
    toolbar, textvariable=protocol_var,
    values=["ALL", "TCP", "UDP", "ICMP", "OTHER"],
    state="readonly", width=10
)
protocol_box.pack(side="left", ipady=3)

# ---------- PACKET TABLE ----------
table_frame = tk.Frame(root, bg=BG)
table_frame.pack(fill="both", expand=True, padx=20, pady=5)

columns = ("time", "source", "destination", "protocol", "size")

style = ttk.Style()
style.theme_use("clam")

style.configure(
    "Treeview",
    background="#07100a",
    foreground=GREEN,
    fieldbackground="#07100a",
    rowheight=27,
    font=("Consolas", 10),
    borderwidth=0
)

style.configure(
    "Treeview.Heading",
    background="#173a20",
    foreground=GREEN,
    font=("Consolas", 10, "bold"),
    relief="flat"
)

style.map(
    "Treeview",
    background=[("selected", "#245c30")],
    foreground=[("selected", "white")]
)

table = ttk.Treeview(
    table_frame, columns=columns,
    show="headings", selectmode="browse"
)

headings = [
    ("time", "TIME", 120),
    ("source", "SOURCE IP", 220),
    ("destination", "DESTINATION IP", 220),
    ("protocol", "PROTOCOL", 120),
    ("size", "SIZE (BYTES)", 130)
]

for col, title, width in headings:
    table.heading(col, text=title)
    table.column(col, width=width, anchor="center")

scrollbar = ttk.Scrollbar(
    table_frame, orient="vertical",
    command=table.yview
)
table.configure(yscrollcommand=scrollbar.set)
table.pack(side="left", fill="both", expand=True)
scrollbar.pack(side="right", fill="y")


# ---------- FILTER TABLE ----------
def refresh_table(*args):
    query = search_var.get().strip().lower()
    selected_protocol = protocol_var.get()

    for item in table.get_children():
        table.delete(item)

    with data_lock:
        rows = list(packet_rows)

    for row in reversed(rows):
        searchable = " ".join(str(v) for v in row).lower()

        protocol_matches = (
            selected_protocol == "ALL"
            or row[3] == selected_protocol
        )

        if protocol_matches and query in searchable:
            table.insert("", "end", values=row)


search_var.trace_add("write", refresh_table)
protocol_box.bind("<<ComboboxSelected>>", refresh_table)


# ---------- PACKET CAPTURE ----------
def process_packet(packet):
    if not packet.haslayer(IP):
        return

    if packet.haslayer(TCP):
        protocol = "TCP"
    elif packet.haslayer(UDP):
        protocol = "UDP"
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
    else:
        protocol = "OTHER"

    row = (
        datetime.now().strftime("%H:%M:%S"),
        packet[IP].src,
        packet[IP].dst,
        protocol,
        len(packet)
    )

    root.after(0, lambda r=row: add_packet(r))


def add_packet(row):
    global total_packets, total_bytes

    if not root.winfo_exists():
        return

    with data_lock:
        packet_rows.append(row)
        total_packets += 1
        total_bytes += int(row[4])
        counts[row[3]] += 1

        # Keep memory use under control.
        if len(packet_rows) > 2000:
            packet_rows.pop(0)

        current_total = total_packets
        current_bytes = total_bytes
        current_counts = counts.copy()

    total_value.config(text=str(current_total))
    tcp_value.config(text=str(current_counts["TCP"]))
    udp_value.config(text=str(current_counts["UDP"]))
    icmp_value.config(text=str(current_counts["ICMP"]))
    bytes_value.config(text=f"{current_bytes:,}")

    refresh_table()


def capture_worker():
    global capturing

    try:
        # Stop filter is checked when packets arrive.
        sniff(
            prn=process_packet,
            store=False,
            stop_filter=lambda packet: stop_event.is_set()
        )
    except Exception as error:
        try:
            root.after(
                0, lambda msg=str(error): show_capture_error(msg)
            )
        except RuntimeError:
            pass
    finally:
        capturing = False
        try:
            root.after(0, capture_stopped)
        except RuntimeError:
            pass


def show_capture_error(error):
    status_label.config(
        text="● CAPTURE ERROR",
        fg=RED
    )
    messagebox.showerror(
        "Capture Error",
        "Packet capture could not start.\n\n"
        + error[:500]
        + "\n\nCheck Npcap installation and permissions. "
        "On Windows, administrator access may be needed."
    )


def start_capture():
    global capturing, capture_thread

    if capturing:
        return

    stop_event.clear()
    capturing = True
    status_label.config(text="● MONITORING ACTIVE", fg=GREEN)

    capture_thread = Thread(
        target=capture_worker,
        daemon=True
    )
    capture_thread.start()


def stop_capture():
    if not capturing:
        status_label.config(text="● SYSTEM READY", fg=YELLOW)
        return

    stop_event.set()
    status_label.config(
        text="● STOP REQUESTED — waiting for packet",
        fg=YELLOW
    )


def capture_stopped():
    status_label.config(
        text="● MONITORING STOPPED",
        fg=YELLOW
    )


# ---------- CLEAR TABLE ----------
def clear_table():
    with data_lock:
        packet_rows.clear()

    for item in table.get_children():
        table.delete(item)

    status_label.config(text="● TABLE CLEARED", fg=YELLOW)


# ---------- RESET STATISTICS ----------
def reset_stats():
    global total_packets, total_bytes

    if capturing:
        messagebox.showwarning(
            "Capture Active",
            "Stop capture before resetting statistics."
        )
        return

    with data_lock:
        packet_rows.clear()
        total_packets = 0
        total_bytes = 0

        for key in counts:
            counts[key] = 0

    total_value.config(text="0")
    tcp_value.config(text="0")
    udp_value.config(text="0")
    icmp_value.config(text="0")
    bytes_value.config(text="0")

    refresh_table()
    status_label.config(text="● STATISTICS RESET", fg=YELLOW)


# ---------- EXPORT CSV ----------
def export_csv():
    with data_lock:
        rows = list(packet_rows)

    if not rows:
        messagebox.showinfo(
            "No Data",
            "Capture some packets before exporting."
        )
        return

    path = filedialog.asksaveasfilename(
        title="Export captured packets",
        defaultextension=".csv",
        filetypes=[("CSV files", "*.csv")],
        initialfile="captured_packets.csv"
    )

    if not path:
        return

    try:
        with open(path, "w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow([
                "Timestamp", "Source IP",
                "Destination IP", "Protocol", "Packet Size"
            ])
            writer.writerows(rows)

        messagebox.showinfo(
            "Export Complete",
            f"Saved {len(rows)} rows to:\n{path}"
        )
    except OSError as error:
        messagebox.showerror("Export Error", str(error))


# ---------- SAVE SUMMARY ----------
def save_summary():
    with data_lock:
        current_total = total_packets
        current_bytes = total_bytes
        current_counts = counts.copy()

    path = filedialog.asksaveasfilename(
        title="Save summary report",
        defaultextension=".txt",
        filetypes=[("Text files", "*.txt")],
        initialfile="summary_report.txt"
    )

    if not path:
        return

    try:
        with open(path, "w", encoding="utf-8") as file:
            file.write("NETWATCH - PACKET SUMMARY\n")
            file.write("=" * 32 + "\n")
            file.write(
                f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            )
            file.write(f"Total packets: {current_total}\n")
            file.write(f"Total bytes: {current_bytes}\n")

            for name, value in current_counts.items():
                file.write(f"{name}: {value}\n")

        messagebox.showinfo(
            "Report Saved",
            f"Report saved to:\n{path}"
        )
    except OSError as error:
        messagebox.showerror("Save Error", str(error))


# ---------- BUTTONS ----------
controls = tk.Frame(root, bg=BG)
controls.pack(fill="x", padx=20, pady=12)


def make_button(parent, text, command, fg=GREEN):
    return tk.Button(
        parent,
        text=text,
        command=command,
        bg=PANEL,
        fg=fg,
        activebackground=fg,
        activeforeground="black",
        font=("Consolas", 9, "bold"),
        padx=12,
        pady=9,
        relief="flat",
        cursor="hand2"
    )


make_button(
    controls, "▶ START CAPTURE", start_capture
).pack(side="left", padx=(0, 6))

make_button(
    controls, "■ STOP CAPTURE", stop_capture, YELLOW
).pack(side="left", padx=6)

make_button(
    controls, "CLEAR TABLE", clear_table, YELLOW
).pack(side="left", padx=6)

make_button(
    controls, "RESET STATS", reset_stats, RED
).pack(side="left", padx=6)

make_button(
    controls, "⇩ EXPORT CSV", export_csv
).pack(side="left", padx=6)

make_button(
    controls, "SAVE SUMMARY", save_summary
).pack(side="left", padx=6)

# ---------- FOOTER ----------
tk.Label(
    root,
    text="NETWATCH | Monitor only networks you own or are authorized to test",
    bg=BG, fg=MUTED, font=("Consolas", 9)
).pack(pady=(0, 10))


def on_close():
    stop_event.set()
    root.destroy()


root.protocol("WM_DELETE_WINDOW", on_close)
root.mainloop()
