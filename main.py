from scapy.all import ARP, Ether, srp

IP_adress = "192.168.1.187"
default_gateway = "192.168.1.1"

def get_MAC_adress():
    global IP_adress
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=IP_adress)
    answered, unanswered = srp(request, timeout=2, verbose=False)
    MAC_adress = answered[0][1].hwsrc
    return MAC_adress
