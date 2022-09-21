import packet_sniffer as ps
import socket
import time

start = time.time()
arp = {}

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
while True: 
    time.sleep(1)
    raw_data, addr = s.recvfrom(1518)
    eth = ps.ethernet_head(raw_data)
    if eth[2] == 8:
        ipv4 = ps.ipv4_head(eth[3])

        if ipv4[4] not in arp:
            arp.update({ipv4[4] : eth[1]})
        if ipv4[5] not in arp:
            arp.update({ipv4[5] : eth[0]})
            
        
    end = time.time()
    if (end - start) > 60:
        print("IP\t\t\t\tMAC")
        for ip in arp.keys():
            print("{}\t->\t{}".format(ip, arp[ip]))
        break