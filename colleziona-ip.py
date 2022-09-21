import packet_sniffer as ps
import socket
import time

src_ip = []
dest_ip = [] 
public_ip = []
start = time.time()

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
while True: 
    time.sleep(1)
    raw_data, addr = s.recvfrom(1518)
    eth = ps.ethernet_head(raw_data)
    if eth[2] == 8:
        ipv4 = ps.ipv4_head(eth[3])

        if ipv4[4] not in src_ip:
            src_ip.append(ipv4[4])
        if ipv4[5] not in dest_ip:
            dest_ip.append(ipv4[5])

        if ps.ip_privato(ipv4[4]) == False:
            public_ip.append(ipv4[4])
        if ps.ip_privato(ipv4[5]) == False:
            public_ip.append(ipv4[5])
        
    end = time.time()
    if (end - start) > 60:
        print("src IP:")
        print(src_ip)
        print("dest IP:")
        print(dest_ip)
        print("public IP:")
        print(public_ip)
        break