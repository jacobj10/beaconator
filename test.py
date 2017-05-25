import time
from threading import Thread

from scapy.all import Dot11,Dot11Beacon,Dot11Elt,RadioTap,sendp,sniff, Ether

netSSID = 'testSSID'       #Network name here
iface = 'mon0'         #Interface name here

def sniff_packets():
    resp = sniff(iface=iface,  lfilter=is_resp)

def is_resp(pkt):
    if pkt.getlayer('Dot11').fields['addr1'] == '22:22:22:22:22:22':
        print 11
    return False

def exand(pkt):
    yield pkt.name
    while pkt.payload:
        pkt = pkt.payload
        yield pkt.name

dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',
addr2='22:22:22:22:22:22', addr3='33:33:33:33:33:33')
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
