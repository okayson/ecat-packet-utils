# NOTE

dpktを使ってEtherCATパケット解析モジュールを作成するにあたり調べた事柄などのメモ。

## dpkt information

[dpkt github](https://github.com/kbandla/dpkt)  
[dpkt doc](https://dpkt.readthedocs.io/en/latest/index.html)  

## Install dpkt 

```sh
pip3 install dpkt
```

## How to create additional dpkt parser

[key concept of creating protocol parsers in dpkt](https://kbandla.github.io/dpkt/creating_parsers.html)

`unpack`とは ... byte列からobjectへの変換  
`pack`とは ... objectからbyte列への変換。  

### unpacking

Note: dpkt.Packeから派生したクラスをselfと表記する。  
dpkt.Packet.__init__()は、dpkt.Packet.unpack()を呼び出す。  
self.unpack()が定義されていればそれが呼び出される。  
self.unpack()が定義されていなければdpkt.Packet.unpack()が呼び出される。  
dpkt.Packet.unpack()では、`__hdr__`が定義されていればそれをparseして、`__hdr__`で定義したタプルと同じ名前のプロパティに値を格納する。未解析分は`self.data`に格納する。  
self.unpack()を定義した場合も、`__hdr__`を解析するために、dpkt.Packet.unpack()を呼び出す必要がある。

### packing

`bytes(obj)`の呼び出しにより、`self.__byte__(obj)`が呼び出される。
`dpkt.Packet.__byte__()`は以下を実行する。
* `self.pack_hdr()`を呼び出す。
* `self.pack_hdr()`の結果＋`bytes(self.data)`呼び出しの結果をreturnする。
以下のような再帰的な呼び出しによるオブジェクト生成が可能。

```
Ethernet(..,data=IP(.., data=TCP(...)))
```

dpkt.Packet.pack_hdr()は`__hdr__`の内容をunpackする。

### printing

`__repr__` ... デフォルト値は表示しない。
`ppprint()` ... 全て表示する。

```
# repr() is called.
>>> ip 
>>> ip.pprint()
```

## About EtherCAT

[EtherCAT (Wireshark wiki)](https://wiki.wireshark.org/Protocols/ethercat)  
[EtherCAT pcap](https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/ethercat.cap.gz)  

以下でEtherCATのサンプルキャプチャファイルを取得できる。
```sh
$ curl https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/ethercat.cap.gz -o ./test_cap/ethercat.cap.gz
$ gzip -d ./data/ethercat.cap.gz
```

