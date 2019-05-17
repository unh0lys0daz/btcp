#!/usr/local/bin/python3
import socket, argparse
from struct import *
import bTCP

#Handle arguments
parser = argparse.ArgumentParser()
parser.add_argument("-w", "--window", help="Define bTCP window size", type=int, default=100)
parser.add_argument("-t", "--timeout", help="Define bTCP timeout in milliseconds", type=int, default=100)
parser.add_argument("-o","--output", help="Where to store file", default="output.txt")
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

    #Receiving Syn, sending Syn_Ack
    (stream_id,syn_rec, ack_rec, flag_rec, window_rec, size_rec, checks_rec, junk) = unpack(packet_format, data)
    checksum = bTCP.get_checksum(stream_id, syn_rec, ack_rec, flag_rec, window_rec, size_rec, junk)
    if checksum != checks_rec:
        print("Checksum failed")
        continue

    syn_ack_reply = bTCP.make_packet(stream_id, 0, 1, BTCP_SYN | BTCP_ACK, args.window, 0, bytes(1000))
    sock.sendto(syn_ack_reply, addr)

    #Receiving Ack
    while True:
        sock.settimeout(args.timeout)
        try:
            data, addr = sock.recvfrom(1016)
            break
        except socket.timeout:
            print("Timeout")
            sock.sendto(syn_ack_reply, addr)
            continue
    print("Got here")
    ack_tuple = unpack(packet_format, data)
    ack_stream_ID = ack_tuple[0]
    ack_FLAGS = ack_tuple[3]
    ack_checksum = ack_tuple[6]
    if (ack_FLAGS != BTCP_ACK):
        print("Corrupt ACK")

    #Receiving data
    file_done = False
    file_handle = open(args.output, 'wb')
    seq = 1
    while not file_done:
        for i in range(args.window):
            data, addr = sock.recvfrom(1016)
            data_tuple = unpack(packet_format, data)
            data_FLAGS = data_tuple[3]
            data_size = data_tuple[5]
            seq += data_size
            data_data = data_tuple[7] #Retrieving the data from the packet
            if (data_FLAGS & BTCP_FIN) != BTCP_FIN:
                file_handle.write(data_data[:data_size])
            else: #Received FIN flag, final packet has been received and transfer is complete
                file_done = True
                break
        if file_done:
            break
        reply = bTCP.make_packet(stream_id, 1, seq, BTCP_ACK, args.window, 0, bytes(1000))
        sock.sendto(reply, addr)

    #Handshake for finishing tcp connection
    #We assume we've already received the FIN packet in this situation because of the above loop
    new_ack = data_tuple[2] + 1 #Increase the ack value by one
    new_syn = data_tuple[1]     #syn number stays the same
    new_FLAGS = BTCP_FIN | BTCP_ACK
    finack_reply = bTCP.make_packet(data_tuple[0], new_syn, new_ack, new_FLAGS, data_tuple[4], 0, bytes(1000))
    sock.sendto(finack_reply, addr)  #Sending the FIN_ACK

    #Receiving the final ACK and closing the connection
    data, addr = sock.recvfrom(1016)
    data_tuple = unpack(packet_format, data)
    if data_tuple[3] != BTCP_ACK:
        print("Error in handshake, didn't receive final ACK")
    sock.close() #Closing the connection
    break
