import socket
import struct

def get_mac(mac_string):
    return mac_string.hex(":") #':'.join('%02x' % ord(b) for b in mac_string)

def ethernet_head(raw_data):
    dest_mac, src_mac, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
    dest_mac = get_mac(bytes(dest_mac))
    src_mac = get_mac(bytes(src_mac))
    proto_network = socket.htons(prototype)
    datagram = raw_data[14:]
    return dest_mac, src_mac, proto_network, datagram

def stampa_eth_header(eth):
    print('\nEthernet Header:')
    print('MAC dest: {}, MAC source: {}, Network protocol: {}'.format(eth[0], eth[1], eth[2]))

def get_ip(addr): 
    return '.'.join(map(str, addr))      

def ipv4_head(raw_data):
    version_header_length = raw_data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, transport_protocol, src_IP, dst_IP = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    segment = raw_data[header_length:]
    src_IP = get_ip(src_IP)
    dst_IP = get_ip(dst_IP)
    return version, header_length, ttl, transport_protocol, src_IP, dst_IP, segment

def ipv6_head(raw_data):
    version = raw_data[0] >> 4
    lenght, ttl, transport_protocol = struct.unpack('! 16s 8s 8s', raw_data[:20])
    src_IP, dest_IP = struct.unpack('! >QQ >QQ', raw_data[:8])
    data = raw_data[:40]
    return version, lenght, ttl, transport_protocol, src_IP, dest_IP, data

def tcp_head(raw_data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags, recv_window, checksum, urg_data_ptr) = struct.unpack('! H H L L H H H H', raw_data[:20])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    data = raw_data[offset:]
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data, recv_window, checksum, urg_data_ptr

def udp_head(raw_data):
    (src, dst, lenght, checksum) = struct.unpack('! H H H H', raw_data[:8])
    data = raw_data[8:]
    return src, dst, lenght, checksum, data


def stampa_ipv4_header(ipv4):
    print( '\t - ' + 'IPv4 Header:')
    print('\t\t - ' + 'Version: {}, Header Length: {}, TTL:{},'.format(ipv4[0], ipv4[1], ipv4[2]))
    print('\t\t - ' + 'Transport Protocol: {}, Source: {}, Target:{}'.format(ipv4[3], ipv4[4], ipv4[5]))
    
def stampa_ipv6_header(ipv6):
    print( '\t - ' + 'IPv6 Header:')
    print('\t\t - ' + 'Version: {}, Fragment Length: {}, TTL:{},'.format(ipv6[0], ipv6[1], ipv6[3]))
    print('\t\t - ' + 'Transport Protocol: {}, Source: {}, Target:{}'.format(ipv6[2], ipv6[4], ipv6[5]))
  
def stampa_tcp_header(tcp): 
    print('\t\t -' + 'TCP Segment:')
    print('\t\t\t -' + 'Source Port: {}, Destination Port: {}'.format(tcp[0], tcp[1]))
    print('\t\t\t -' + 'Sequence: {}, Acknowledgment: {}'.format(tcp[2], tcp[3]))
    print('\t\t\t -' + 'Flags:')
    print('\t\t\t -' + 'URG: {}, ACK: {}, PSH:{}'.format(tcp[4], tcp[5], tcp[6]))
    print('\t\t\t -' + 'RST: {}, SYN: {}, FIN:{}'.format(tcp[7], tcp[8], tcp[9]))
    print('\t\t\t -' + 'Receive window: {}, Checksum: {}, Urgent Data Pointer:{}'.format(tcp[11], tcp[12], tcp[13]))
    
def stampa_udp_header(udp):
    print('\t\t -' + 'UDP Segment:')
    print('\t\t\t -' + 'Source Port: {}, Destination Port: {}'.format(udp[0], udp[1]))
    print('\t\t\t -' + 'Lenght: {}, Checksum: {}'.format(udp[2], udp[3]))
    
# https://stackoverflow.com/questions/166506/finding-local-ip-addresses-using-pythons-stdlib
def get_my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(('10.254.254.254', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def get_my_mac():
    return "b0:68:e6:bc:2e:f1"

import re
import json
from urllib.request import urlopen

def info_ip(ip):
    url = 'http://ipinfo.io/'+ip
    response = urlopen(url)
    data = json.load(response)
    org=data['org']
    city = data['city']
    country=data['country']
    region=data['region']
    return org, city, country, region

def ip_privato(ipv4):
    if ipv4.startswith("192.") or ipv4.startswith("10.") or ipv4.startswith("127."):
        return True
    else:
        return False