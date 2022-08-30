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

#### Trouble Shooting

##### The error is generated when 'pcapng' file is parsed.

The error is generated when 'pcapng' file is parsed.  
Please convert file format from 'pcapng' to 'pcap' by wireshark.  

```sh
$ ./ecsplitdatagram.py /path/to/capture.pcapng
Traceback (most recent call last):
  File "./ecsplitdatagram.py", line 81, in <module>
    main()
  File "./ecsplitdatagram.py", line 78, in main
    split_packets(args.input, output_filename)
  File "./ecsplitdatagram.py", line 45, in split_packets
    pcap_reader = dpkt.pcap.Reader(fread)
  File "/home/foo/.local/lib/python3.8/site-packages/dpkt/pcap.py", line 285, in __init__
    raise ValueError('invalid tcpdump header')
ValueError: invalid tcpdump header
```

## About ethercat package

`./ethercat` is python package to handle ethercat packet captured file.  
See [ethercat/README.md](ethercat/README.md) for details.  


## Related information

### dpkt

[dpkt github](https://github.com/kbandla/dpkt)  
[dpkt document](https://dpkt.readthedocs.io/en/latest/index.html)  



