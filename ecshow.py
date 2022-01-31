#!/usr/bin/env python3

import argparse
import dpkt
import ethercat

def filter_frame(eth):
    if eth.type != 0x88a4:
        return 
    # If you want to filter specific ethernet frame, return True.
    return False

def filter_datagram(datagram):
    # If you want to filter specific datagram, return True.
    # e.g. --->
    # if datagram.wkc == 0:
    #     return True
    # e.g. <---
    return False

def show_packet(no, ts, buf):
    eth = dpkt.ethernet.Ethernet(buf)
    if filter_frame(eth):
        return 

    print('Frame[{0}](----- TimeStamp: {1:.6f}, Dst: {2}, Src: {3} -----)'.
            format(no, ts, eth.dst.hex(), eth.src.hex()))

    ecat = ethercat.EtherCAT(eth.data)

    datagram_count = 0
    for datagram in ecat.datagrams:
        datagram_count += 1
        if filter_datagram(datagram):
            continue
        print('Frame[{}].Datagram[{:2d}] cmd={}, idx={}, addr={}, offset={}, data={}, wkc={}'.
                format(no, datagram_count-1, datagram.cmd, datagram.index, datagram.slaveaddr, 
                       hex(datagram.offsetaddr), datagram.data, datagram.wkc))
        # datagram.pprint()

def show_packets(filename):

    f = open(filename, 'rb')
    pcap = dpkt.pcap.Reader(f)
    packet_count = 0

    for ts, buf in pcap:
        packet_count += 1
        show_packet(packet_count, ts, buf)

    f.close()
    print('Packt Count:', packet_count)

def main():

    parser = argparse.ArgumentParser(description='Show EtherCAT captured packets.')
    parser.add_argument('filename', help='pcap file')
    args = parser.parse_args()

    show_packets(args.filename)

if __name__ == '__main__':
    main()

# vim: fdm=marker
