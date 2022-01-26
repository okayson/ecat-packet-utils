# How to run tests
# $ cd /path/to/this-directory
# $ pytest
# 
# Note: Easily run from vim
#   Run the tests with <F6> when this file is opened in vim-buffer.
#   => nmap <F6> :!pytest %<CR>

import pytest
import dpkt
import copy
import ethercat

def test_ecat_create_empty():
    ecat = ethercat.EtherCAT()
    assert len(ecat) == 2
    assert ecat.type == 1
    assert ecat.length == 0

def test_datagram_empty():
    datagram = ethercat.EtherCATDatagram()
    assert len(datagram) == 10+2
    assert datagram.cmd == 0
    assert datagram.slaveaddr == 0
    assert datagram.offsetaddr == 0
    assert datagram.interrupt == 0

    assert datagram.more == 0
    assert datagram.roundtrip == 0
    assert datagram.length == 0

    assert datagram.wkc == 0

def test_construct_ecat():
    ecat = ethercat.EtherCAT()
    datagram = ethercat.EtherCATDatagram()
    datagram.data = (b'\x11\x00')

    ecat.datagrams.append(copy.copy(datagram))
    ecat.datagrams.append(copy.copy(datagram))
    ecat.datagrams.append(copy.copy(datagram))

    assert len(ecat) == (2+14*3)
    assert ecat.length == (14*3)
    assert ecat.datagrams[0].more == 1
    assert ecat.datagrams[1].more == 1
    assert ecat.datagrams[2].more == 0

def test_construct_ecat2():
    ecat = ethercat.EtherCAT()
    data = (b'\x01\x06\x04\x00\x30\x01\x02\x00\x04\x00\x08\x00\x01\x00')

    ecat.datagrams.append(ethercat.EtherCATDatagram(data))
    ecat.datagrams.append(ethercat.EtherCATDatagram(data))
    ecat.datagrams.append(ethercat.EtherCATDatagram(data))

    assert len(ecat) == (2+14*3)
    assert ecat.length == (14*3)
    assert ecat.datagrams[0].more == 1
    assert ecat.datagrams[1].more == 1
    assert ecat.datagrams[2].more == 0

def test_construct_ecat3():
    ecat = ethercat.EtherCAT()
    data = (b'\x11\x00')
    datagram = ethercat.EtherCATDatagram()

    ecat.datagrams.append(ethercat.EtherCATDatagram(data=data))
    ecat.datagrams.append(ethercat.EtherCATDatagram(data=data))
    ecat.datagrams.append(ethercat.EtherCATDatagram(data=data))

    assert len(ecat) == (2+14*3)
    assert ecat.length == (14*3)
    assert ecat.datagrams[0].more == 1
    assert ecat.datagrams[0].length == 2
    assert ecat.datagrams[1].more == 1
    assert ecat.datagrams[1].length == 2
    assert ecat.datagrams[2].more == 0
    assert ecat.datagrams[2].length == 2

def test_loading_packet():
    input_file  = './test_cap/ethercat_one.cap'

    fdr = open(input_file, 'rb')
    pcap_reader = dpkt.pcap.Reader(fdr)

    for ts, buf in pcap_reader:

        src_eth = dpkt.ethernet.Ethernet(buf)
        src_ecat = ethercat.EtherCAT(src_eth.data)

        assert src_ecat.length == 0x62
        assert src_ecat.type == 0x1

        assert len(src_ecat.datagrams) == 7

        assert len(src_ecat.datagrams[0]) == 14
        assert src_ecat.datagrams[0].cmd == 0x8
        assert src_ecat.datagrams[0].index == 0x3
        assert src_ecat.datagrams[0].slaveaddr == 0x5
        assert src_ecat.datagrams[0].offsetaddr == 0x120
        assert src_ecat.datagrams[0].length == 2
        assert src_ecat.datagrams[0].roundtrip == 0
        assert src_ecat.datagrams[0].more == 1
        assert src_ecat.datagrams[0].interrupt == 0x4

        assert len(src_ecat.datagrams[-1]) == 14
        assert src_ecat.datagrams[-1].cmd == 0x1
        assert src_ecat.datagrams[-1].index == 0x9
        assert src_ecat.datagrams[-1].slaveaddr == 0x1
        assert src_ecat.datagrams[-1].offsetaddr == 0x130
        assert src_ecat.datagrams[-1].length == 2
        assert src_ecat.datagrams[-1].roundtrip == 0
        assert src_ecat.datagrams[-1].more == 0
        assert src_ecat.datagrams[-1].interrupt == 0x4

        break

    fdr.close()

def test_dividing_packet():

    # prepareation
    input_file  = './test_cap/ethercat_one.cap'
    output_file = './test_cap/ethercat_one_div.cap'

    fdr = open(input_file, 'rb')
    pcap_reader = dpkt.pcap.Reader(fdr)

    fdw = open(output_file, 'wb')
    pcap_writer = dpkt.pcap.Writer(fdw)

    for ts, buf in pcap_reader:

        src_eth = dpkt.ethernet.Ethernet(buf)
        src_ecat = ethercat.EtherCAT(src_eth.data)

        for datagram in src_ecat.datagrams:
            eth = copy.deepcopy(src_eth)
            ecat = copy.deepcopy(src_ecat)
            ecat.datagrams.clear()
            ecat.datagrams.append(datagram)
            eth.data = bytes(ecat)
            pcap_writer.writepkt(eth, ts)

    fdr.close()
    fdw.close()

    # validation
    input_file  = output_file

    fdr = open(input_file, 'rb')
    pcap_reader = dpkt.pcap.Reader(fdr)

    count = 0
    for ts, buf in pcap_reader:
        src_eth = dpkt.ethernet.Ethernet(buf)
        src_ecat = ethercat.EtherCAT(src_eth.data)

        if count == 0:
            assert src_ecat.length == 14
            assert len(src_ecat.datagrams) == 1
            assert len(src_ecat.datagrams[0]) == 14
            assert src_ecat.datagrams[0].cmd == 0x8
            assert src_ecat.datagrams[0].index == 0x3
            assert src_ecat.datagrams[0].slaveaddr == 0x5
            assert src_ecat.datagrams[0].offsetaddr == 0x120
            assert src_ecat.datagrams[0].length == 2
            assert src_ecat.datagrams[0].roundtrip == 0
            assert src_ecat.datagrams[0].more == 0
            assert src_ecat.datagrams[0].interrupt == 0x4
        if count == 6:
            assert len(src_ecat.datagrams[-1]) == 14
            assert src_ecat.datagrams[-1].cmd == 0x1
            assert src_ecat.datagrams[-1].index == 0x9
            assert src_ecat.datagrams[-1].slaveaddr == 0x1
            assert src_ecat.datagrams[-1].offsetaddr == 0x130
            assert src_ecat.datagrams[-1].length == 2
            assert src_ecat.datagrams[-1].roundtrip == 0
            assert src_ecat.datagrams[-1].more == 0
            assert src_ecat.datagrams[-1].interrupt == 0x4
        count += 1

    assert count == 7

    fdr.close()

# vim: fdm=marker
