# $Id: ethercat.py $
# -*- coding: utf-8 -*-
"""EtherCAT Protocol."""

import dpkt
import struct

# EtherCAT "{{{

ECAT_WKC_LEN = 2

class EtherCAT(dpkt.Packet):
    """EtherCAT Protocol.

    Attributes:
        __hdr__: Header fields of EtherCAT.
        type: Protocol type. Only EtherCAT commands (Type = 0x1) are supported by ESCs.
        length: length of the EtherCAT datagrams
        datagrams: list of the EtherCAT datagram
    """

    __byte_order__ = '<'
    __hdr__ = (
        ('_type_length', 'H', (1 << 12)),
    )
    __bit_fields__ = {
        '_type_length': (
            ('type', 4),        # type, 4bit
            ('_rsv', 1),        # reserved, 1bit
            ('length', 11)      # length, 11bit
        )
    }

    def __init__(self, *args, **kwargs):
        self.datagrams = []
        super().__init__(*args, **kwargs)

    def __len__(self):
        self._pack_data()
        return self.__hdr_len__ + self.length

    def __bytes__(self):
        self._pack_data()
        return self.pack_hdr() + bytes(self.data)

    def _pack_data(self):
        self.length = 0
        self.data = bytes()
        for datagram in self.datagrams:
            datagram.more = 0 if datagram == self.datagrams[-1] else 1
            self.length += len(datagram)
            self.data += bytes(datagram)

    def pack(self):
        bytes(self) # invoke '__bytes__' to packing

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)

        self.datagrams = []
        pos = 0

        while True:
            datagram = EtherCATDatagram(self.data[pos:])
            self.datagrams.append(datagram)
            pos += len(datagram)
            if datagram.more == 0:
                break

# EtherCAT "}}}

# EtherCAT Datagram "{{{

class EtherCATDatagram(dpkt.Packet):
    """EtherCAT Datagram.

    Attributes:
        __hdr__: Header fields of EtherCAT Datagram.
        wkc: Working counter
    """
    __byte_order__ = '<'
    __hdr__ = (
        ('cmd', 'B', 0),
        ('index', 'B', 0),
        ('slaveaddr', 'H', 0),  # TODO: Need support APxx, FPxx, Lxx. Divide attributes.
        ('offsetaddr', 'H', 0),
        ('_more_roundtrip_length', 'H', 0),
        ('interrupt', 'H', 0),
    )
    __bit_fields__ = {
        '_more_roundtrip_length': (
            ('more', 1),            # More EtherCAT datagram
            ('roundtrip', 1),        # Round trip
            ('_rsv', 3),
            ('length', 11)          # Length
        )
    }
    __pprint_funcs__ = {
        'interrupt': hex,
        'offsetaddr': hex,
    }

    def __init__(self, *args, **kwargs):
        self.wkc = 0
        super().__init__(*args, **kwargs)

    def __len__(self):
        return self.__hdr_len__ + len(self.data) + ECAT_WKC_LEN

    def __bytes__(self):
        self.length = len(self.data)
        return self.pack_hdr() + bytes(self.data) + struct.pack('<H', self.wkc)

    def pack(self):
        bytes(self) # invoke '__bytes__' to packing

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.wkc = struct.unpack('<H', self.data[self.length:self.length+2])[0]
        self.data = self.data[:self.length]

# EtherCAT Datagram "}}}

# vim: fdm=marker
