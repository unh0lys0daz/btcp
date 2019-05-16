#!/usr/local/bin/python3
import socket, argparse
from struct import *

#Handle arguments
parser = argparse.ArgumentParser()
parser.add_argument("-w", "--window", help="Define bTCP window size", type=int, default=100)
parser.add_argument("-t", "--timeout", help="Define bTCP timeout in milliseconds", type=int, default=100)
parser.add_argument("-o","--output", help="Where to store file", default="tmp.file")
args = parser.parse_args()

server_ip = "127.0.0.1"
server_port = 9001

#Define a header format
header_format = "I"

BTCP_FIN = 0x1
BTCP_SYN = 0x2
BTCP_ACK = 0x4
BTCP_RST = 0x8

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
sock.bind((server_ip, server_port))

while True:
    data, addr = sock.recvfrom(1016)
    print(unpack(header_format,data))

    #Going through the handshake
    syn_tuple = unpack(header_format, data)
    syn_stream_ID = syn_tuple[0]
    syn_SYN = syn_tuple[1]
    syn_ACK = syn_tuple[2]
    syn_FLAGS = syn_tuple[3]
    syn_window_size = syn_tuple[4]
    syn_data_length = syn_tuple[5]
    syn_checksum = syn_tuple[6]

    syn_ack_reply = pack(header_format, syn_stream_ID, 0, 1, BTCP_SYN | BTCP_ACK, syn_window_size, syn_data_length, syn_checksum)
    sock.sendto(syn_ack_reply, addr)

