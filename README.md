# ecat-packet-utils

This is a utility that manipulate EtherCAT packets(e.g.`*.cap`, `*.pcap`) using Python.

## Requirements

* Python3 (It has been confirmed to work with version 3.9.9)
* Python module : dpkt

Installing the aboves.
```sh
$ sudo apt install python3
$ sudo apt install python3-pip
$ pip3 install dpkt
$ pip3 install pytest
```

## Utilities

The usage of each script is shown by `scriptname -h`.  

### ecshow.py

Show ethercat frames.  
If you want to filter specific ethernet frame, modify `filter_frame`.  
If you want to filter specific ethercat datagram, modify `filter_datagram`.  

### ecsplitdatagram.py

Split and reconstruct the ethercat datagrams in the pcap file.  
If you want to filter specific ethernet frame, modify `filter_frame`.  
If you want to filter specific ethercat datagram, modify `filter_datagram`.  

## About ethercat package

`./ethercat` is python package to handle ethercat packet captured file.  
See [ethercat/README.md](ethercat/README.md) for details.  


## Related information

### dpkt

[dpkt github](https://github.com/kbandla/dpkt)  
[dpkt document](https://dpkt.readthedocs.io/en/latest/index.html)  



