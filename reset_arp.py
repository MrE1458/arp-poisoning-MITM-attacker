from scapy.all import *
import time

gateway_ip = "192.168.1.254"
gateway_mac = "F8:22:29:26:79:70"
iface = conf.iface

pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, psrc=gateway_ip, pdst=gateway_ip, hwsrc=gateway_mac, hwdst="ff:ff:ff:ff:ff:ff")

for i in range(5):
    sendp(pkt, iface=iface, verbose=False)
    time.sleep(0.5)

print("Sent gratuitous ARP for", gateway_ip, "->", gateway_mac)
