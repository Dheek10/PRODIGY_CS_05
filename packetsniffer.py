from scapy.all import sniff, IP, TCP, UDP, ICMP
def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        # Determine the protocol and extract payload data accordingly
        if proto == 6:  # TCP
            if TCP in packet:
                print(f"[TCP] {ip_src}:{packet[TCP].sport} -> {ip_dst}:{packet[TCP].dport}")
                print(f"Payload: {bytes(packet[TCP].payload)}")
        elif proto == 17:  # UDP
            if UDP in packet:
                print(f"[UDP] {ip_src}:{packet[UDP].sport} -> {ip_dst}:{packet[UDP].dport}")
                print(f"Payload: {bytes(packet[UDP].payload)}")
        elif proto == 1:  # ICMP
            if ICMP in packet:
                print(f"[ICMP] {ip_src} -> {ip_dst}")
                print(f"Payload: {bytes(packet[ICMP].payload)}")
        else:
            print(f"[Other] {ip_src} -> {ip_dst} (Protocol: {proto})")
            print(f"Payload: {bytes(packet.payload)}")

def main():
    # Use the sniff function from scapy to capture packets
    sniff(prn=packet_callback, store=False)

if __name__ == "_main_":
    main()