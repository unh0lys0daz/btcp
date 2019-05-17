#!/usr/local/bin/python3
import socket, argparse, random
from random import randint
from struct import *
import bTCP

#Handle arguments
parser = argparse.ArgumentParser()
parser.add_argument("-w", "--window", help="Define bTCP window size", type=int, default=100)
parser.add_argument("-t", "--timeout", help="Define bTCP timeout in seconds", type=float, default=2.00)
parser.add_argument("-i","--input", help="File to send", default="tmp.file")
args = parser.parse_args()

destination_ip = "127.0.0.1"
destination_port = 9001

#flags
BTCP_FIN = 0x1
BTCP_SYN = 0x2
BTCP_ACK = 0x4
BTCP_RST = 0x8

#bTCP header
header_format = "!IHHBBHI"
packet_format = "!IHHBBHI1000s"

#bTCP_header = pack(header_format, randint(0,100), syn_number, ack_number, flags, window, 1000, checksum)
#bTCP_payload = ""
#udp_payload = bTCP_header

#UDP socket which will transport your bTCP packets
#sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

#send payload
#sock.sendto(udp_payload, (destination_ip, destination_port))



def connect(dest_ip, dest_port):
    pad_data = bytes(1000)
    stream_id = randint(1,100)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    window = args.window
    timeout = args.timeout

    # syn packet creation
    pseudo_header_syn = pack(header_format, stream_id, 0, 0, BTCP_SYN, window, 0, 0)
    bTCP_header_syn = pack(header_format, stream_id, 0, 0, BTCP_SYN, window, 0, bTCP.calculate_checksum(pseudo_header_syn))

    syn_packet = bTCP_header_syn + pad_data
    # send syn
    sock.sendto(syn_packet, (dest_ip, dest_port))
    # recv syn-ack, loop to handle corrupted package
    while True:
        sock.settimeout(args.timeout)
        try:
            (data, addr) = sock.recvfrom(1016)
        except socket.timeout:
            print("Timeout")
            return None
        (syn_nr_synack, ack_nr_synack, flags_synack, window_synack, size_synack, checksum_synack) = unpack(packet_format, data)
        pseudo_header_synack = pack(header_format, stream_id, syn_nr_synack, ack_nr_synack, flags_synack, window_synack, size_synack, 0)
        if bTCP.calculate_checksum(pseudo_header_synack) != checksum_synack:
            print("Checksum synack doesn't match")
            sock.sendto(syn_packet, (dest_ip, dest_port))
        else:
            break


  # ack creation
    pseudo_header_ack = pack(header_format, stream_id, ack_nr_synack, syn_nr_synack+1, BTCP_ACK, window_synack, 0, 0)
    bTCP_header_ack = pack(header_format, stream_id, ack_nr_synack, syn_nr_synack+1, BTCP_ACK, window_synack, 0, bTCP.calculate_checksum(pseudo_header_ack))
    sock.sendto(bTCP_header_ack + data, (dest_ip, dest_port))

    return (stream_id, sock, window_synack)
  # send ack + data (or should we return first and then start off with the first ack (from the handshake)???

def disconnect(stream_id, seq, ack, dest_ip, dest_port, sock):
    packet = bTCP.make_packet( stream_id, seq, ack, BTCP_FIN | BTCP_ACK, args.window, 0, bytes(1000))
    sock.sendto( packet, (dest_ip, dest_port))

    while True:
        sock.settimeout(args.timeout)

        try:
            (data, addr) = sock.recvfrom(1016)
        except socket.timeout:
            print("timeout while disconnecting")
            return False
        (str_id, finack_seq, finack_ack, finack_flags, finack_window, finack_siz, finack_checksum, junk) = unpack(packet_format, data)
        chk = bTCP.get_checksum(str_id, finack_seq, finack_ack, finack_flags, finack_window, finack_siz, junk)
        if finack_checksum != chk:
            print("CORRUPTED PACKET")
            sock.sendto( packet, (dest_ip, dest_port))
        else:
            break
    return True


def send_file(filename, dest_ip, dest_port):
    try:
        stream_id, sock, window = connect(dest_ip, dest_port)
    except:
        print("Connection failed")
        return
    try:
        file_handle = open(filename, 'r')
    except:
        print("Failed to open file, exiting...")
        return
    seq = 1
    ack = 1
    while True:
        file_done = False
        for i in range(window):
            chunk = file_handle.read(1000)
            if len(chunk) == 0:
                file_done = True
                break
            packet = bTCP.make_packet(stream_id, seq, ack, BTCP_ACK, window, len(chunk), chunk)
            sock.sendto( packet, (dest_ip, dest_port))
            seq += len(chunk)

        if file_done:
            break

        # Some nice loop to make handle corrupted packages being received
        while True:
            sock.settimeout(args.timeout)
            try:
                data, addr = sock.recvfrom(1016)
            except socket.timeout:
                print("TIMEOUT")
                return False
            (str_id, syn_recv, seq, flag, window, siz, checksum, junk) = unpack(packet_format, data)
            if checksum != bTCP.get_checksum(str_id, syn_recv, seq, flag, window, siz, junk):
                print("CORRUPTED PACKET")
                sock.sendto( packet, (dest_ip, dest_port))
            else:
                break
    file_handle.close()
    ret_val = disconnect(stream_id, seq, ack, dest_ip, dest_port, sock)
    sock.close()
    if ret_val:
        print("succesfully disconnected")

send_file(args.input, "127.0.0.1", 9001)
