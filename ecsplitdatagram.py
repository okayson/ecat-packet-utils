#!/usr/bin/env python3

import os
import argparse
import datetime
import copy
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

def split_packet(pcap_writer, ts, buf):

    origin_eth = dpkt.ethernet.Ethernet(buf)
    if filter_frame(origin_eth):
        return

    origin_ecat = ethercat.EtherCAT(origin_eth.data)

    for datagram in origin_ecat.datagrams:
        if filter_datagram(datagram):
            continue
        eth  = copy.deepcopy(origin_eth)
        ecat = copy.deepcopy(origin_ecat)
        ecat.datagrams.clear()
        ecat.datagrams.append(datagram)
        eth.data = bytes(ecat)
        pcap_writer.writepkt(eth, ts)

def split_packets(input_filename, output_filename):

    fread = open(input_filename, 'rb')
    pcap_reader = dpkt.pcap.Reader(fread)

    fwrite = open(output_filename, 'wb')
    pcap_writer = dpkt.pcap.Writer(fwrite)

    for ts, buf in pcap_reader:
        split_packet(pcap_writer, ts, buf)

    fread.close()
    fwrite.close()

def make_default_output_filename(input_filename):

    filename, ext = os.path.splitext(input_filename)
    now = datetime.datetime.now()
    return filename + '_' + now.strftime('%Y%m%d_%H%M%S') + ext

def main():

    parser = argparse.ArgumentParser(
            description='Split and reconstruct the EtherCAT datagrams in the pcap file.')
    parser.add_argument(
            'input',
            help='Input file name')
    parser.add_argument(
            '-o', '--output',
            help='Output file name(Default:{input}_datetime.ext)')
    args = parser.parse_args()

    output_filename = args.output
    if output_filename is None:
        output_filename = make_default_output_filename(args.input)

    split_packets(args.input, output_filename)

if __name__ == '__main__':
    main()

# vim: fdm=marker
