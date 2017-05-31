import time
from threading import Thread

from scapy.all import Dot11,Dot11Beacon,Dot11Elt,RadioTap,sendp,sniff, Dot11ProbeResp


netSSID = 'testSSID'       #Network name here
iface = 'mon0'         #Interface name here

def sniff_packets():
    resp = sniff(iface=iface,  prn=is_resp)

def is_resp(packet):
    if len(packet.notdecoded[8:9]) > 0:  # Driver sent radiotap header flags
        # This means it doesn't drop packets with a bad FCS itself
        flags = ord(packet.notdecoded[8:9])
        if flags & 64 != 0:  # BAD_FCS flag is set
            return
    if packet.type == 0:
        if packet.subtype == 0x04:  # Probe request
            if Dot11Elt in packet:
                ssid = packet[Dot11Elt].info

                print("Probe request for SSID {} by MAC {}".format(ssid, packet.addr2))
                if ssid == netSSID or (Dot11Elt in packet and packet[Dot11Elt].len == 0):
                    send_probe_resp(packet.addr2)

def send_probe_resp(target):
    dot11 = Dot11(type=0, subtype=5, addr1='ff:ff:ff:ff:ff:ff',
    addr2='22:22:22:22:22:22', addr3='22:22:22:22:22:22')
    probe = Dot11ProbeResp(beacon_interval=0x0064, cap=0x2104)
    essid = essid = Dot11Elt(ID='SSID',info=netSSID, len=len(netSSID))
    resp_frame = RadioTap()/dot11/probe/essid
    sendp(resp_frame, iface=iface, verbose=False)

dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',
addr2='22:22:22:22:22:22', addr3='22:22:22:22:22:22')
beacon = Dot11Beacon(cap='ESS+privacy')
essid = Dot11Elt(ID='SSID',info=netSSID, len=len(netSSID))
rsn = Dot11Elt(ID='RSNinfo', info=(
'\x01\x00'                 #RSN Version 1
'\x00\x0f\xac\x02'         #Group Cipher Suite : 00-0f-ac TKIP
'\x02\x00'                 #2 Pairwise Cipher Suites (next two lines)
'\x00\x0f\xac\x04'         #AES Cipher
'\x00\x0f\xac\x02'         #TKIP Cipher
'\x01\x00'                 #1 Authentication Key Managment Suite (line below)
'\x00\x0f\xac\x02'         #Pre-Shared Key
'\x00\x00'))               #RSN Capabilities (no extra capabilities)

frame = RadioTap()/dot11/beacon/essid/rsn

raw_input("\nPress enter to start\n")


sender = Thread(target=sendp, args=(frame,), kwargs={'iface':iface, 'inter':0.100, 'loop':1})
sender.daemon = True
sender.start()

sniffer = Thread(target=sniff_packets)
sniffer.daemon = True
sniffer.start()

while True:
    time.sleep(1)
