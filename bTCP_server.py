#!/usr/local/bin/python3
import socket, argparse
from struct import *
import bTCP

#Handle arguments
parser = argparse.ArgumentParser()
parser.add_argument("-w", "--window", help="Define bTCP window size", type=int, default=100)
parser.add_argument("-t", "--timeout", help="Define bTCP timeout in milliseconds", type=int, default=100)
parser.add_argument("-o","--output", help="Where to store file", default="tmp.file")
args = parser.parse_args()

server_ip = "127.0.0.1"
server_port = 9001

#Define a header format
header_format = "!IHHBBHI"
packet_format = "!IHHBBHI1000s"

BTCP_FIN = 0x1
BTCP_SYN = 0x2
BTCP_ACK = 0x4
BTCP_RST = 0x8

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
sock.bind((server_ip, server_port))

while True:
    data, addr = sock.recvfrom(1016)
    print(unpack(header_format,data))

    #Receiving Syn, sending Syn_Ack
    syn_tuple = unpack(header_format, data)
    syn_stream_ID = syn_tuple[0]
    syn_SYN = syn_tuple[1]
    syn_ACK = syn_tuple[2]
    syn_FLAGS = syn_tuple[3]
    syn_window_size = syn_tuple[4]
    syn_data_length = syn_tuple[5]
    syn_checksum = syn_tuple[6]

    syn_ack_reply = pack(header_format, syn_stream_ID, 0, 1, BTCP_SYN | BTCP_ACK, syn_window_size, 0, )
    sock.sendto(syn_ack_reply, addr)

    #Receiving Ack
    data, addr = sock.recvfrom(1016)
    ack_tuple = unpack(header_format, data)
    ack_stream_ID = ack_tuple[0]
    ack_FLAGS = ack_tuple[3]
    ack_checksum = ack_tuple[6]
    if (ack_FLAGS != BTCP_ACK) | (ack_checksum != syn_checksum):
        print("Corrupt ACK")

    #Receiving data
    file_done = False
    while not file_done:
        f = open(args.output, 'wb')
        data, addr = sock.recvfrom(1016)
        while(data):
            data_tuple = unpack(packet_format, data)
            data_FLAGS = data_tuple[3]
            data_data = data_tuple[7] #Retrieving the data from the packet
            if data_FLAGS != BTCP_FIN:
                f.write(data_data)
                data, addr = sock.recvfrom(1016)
            elif: #Received FIN flag, final packet has been received and transfer is complete
                file_done = True 

    #Handshake for finishing tcp connection
    #We assume we've already received the FIN packet in this situation because of the above loop
    new_ack = data_tuple[2] + 1 #Increase the ack value by one
    new_syn = data_tuple[1]     #syn number stays the same
    new_FLAGS = BTCP_FIN | BTCP_ACK
    temp_packet = pack(header_format, data_tuple[0], new_syn, new_ack, new_FLAGS, data_tuple[4], 0, 0)#For calculating the checksum
    finack_reply = pack(header_format, data_tuple[0], new_syn, new_ack, new_FLAGS, data_tuple[4], 0, bTCP.calculate_checksum(temp_packet))
    s.sendto(finack_reply, addr)  #Sending the FIN_ACK

    #Receiving the final ACK and closing the connection
    data, addr = sock.recvfrom(1016)
    data_tuple = unpack(header_format, data)
    if data_tuple[3] != BTCP_ACK:
        print("Error in handshake, didn't receive final ACK")
    sock.close() #Closing the connection
