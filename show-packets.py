import socket
import packet_sniffer as ps

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
while True: 
    raw_data, addr = s.recvfrom(1518)
    eth = ps.ethernet_head(raw_data)
    ps.stampa_eth_header(eth)
    if eth[2] == 8:
        ipv4 = ps.ipv4_head(eth[3])
        ps.stampa_ipv4_header(ipv4)
        if ipv4[3] == 6:
            tcp = ps.tcp_head(ipv4[6])
            ps.stampa_tcp_header(tcp)
            print(tcp[10])
        elif ipv4[3] == 17:
            udp = ps.udp_head(ipv4[6])
            ps.stampa_udp_header(udp)
            print(udp[4])
    elif eth[2] == 0x86DD:
        ipv6 = ps.ipv6_head(eth[3])
        ps.stampa_ipv6_header(ipv6)