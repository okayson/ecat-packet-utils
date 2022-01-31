#!/usr/bin/env python3

"""EtherCAT Protocol."""

import dpkt
import struct
# from .compat import iteritems

# Global variables {{{

# Ethernet > ethertype
ETH_TYPE_ECAT = 0x88a4

# EtherCAT > Datagram > Cmd
ECAT_CMD_NOP   = 0  # No Operation
ECAT_CMD_APRD  = 1  # Auto Increment Read
ECAT_CMD_APWR  = 2  # Auto Increment Write  
ECAT_CMD_APRW  = 3  # Auto Increment Read Write 
ECAT_CMD_FPRD  = 4  # Configured Address Read  
ECAT_CMD_FPWR  = 5  # Configured Address Write 
ECAT_CMD_FPRW  = 6  # Configured Address Read Write 
ECAT_CMD_BRD   = 7  # Broadcast Read 
ECAT_CMD_BWR   = 8  # Broadcast Write 
ECAT_CMD_BRW   = 9  # Broadcast Read Write
ECAT_CMD_LRD   = 10 # Logical Memory Read 
ECAT_CMD_LWR   = 11 # Logical Memory Write
ECAT_CMD_LRW   = 12 # Logical Memory Read Write 
ECAT_CMD_ARMW  = 13 # Auto Increment Read Multiple Write 
ECAT_CMD_FRMW  = 14 # Configured Read Multiple Write

# EtherCAT > Datagram > WKC
ECAT_WKC_LEN = 2

# ethercat Module }}}

# EtherCAT "{{{

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

    @classmethod
    def init(cls):
        pass

    @classmethod
    def is_ethercat(cls, eth):
        # eth is instance of Ethernet()
        return (eth.type == ETH_TYPE_ECAT)

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
def get_cmd_name(cmd):
    return EtherCATDatagram.get_cmd_name(cmd)

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
        'cmd': get_cmd_name,
        'offsetaddr': hex,
        'interrupt': hex,
    }

    __cmd_names = {}

    @classmethod
    def init(cls):

        __cmd_names = {}

        g = globals()
        for k, v in g.items():
            if k.startswith('ECAT_CMD_'):
                name = k[9:]
                cls.__cmd_names[v] = name

    @classmethod
    def get_cmd_name(cls, cmd):
        return cls.__cmd_names.get(cmd, None)

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
