from scapy.all import sniff

def show_packet(packet):
    print("PACKET:", len(packet), "bytes |", packet.summary())

print("====================================")
print(" INTELLIGUARD REAL-TIME MONITOR")
print("====================================")
print("Waiting for real network traffic...")
print("Open Chrome and refresh a website.")
print("Press Ctrl+C to stop.")
print()

sniff(
    filter="ip",
    prn=show_packet,
    store=False
)
