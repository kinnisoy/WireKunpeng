# -*- coding: utf-8 -*-
from os import chmod, getcwd, remove
from shutil import copy
from tempfile import NamedTemporaryFile
from threading import Event, Thread
from decimal import Decimal

from PySide2.QtCore import Qt
from PySide2.QtGui import QBrush, QColor
from PySide2.QtWidgets import QFileDialog, QMessageBox, QTreeWidgetItem
from scapy.all import load_layer
from scapy.layers.http import HTTPRequest, HTTPResponse, HTTP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import *
from scapy.layers.inet6 import *
from scapy.layers.l2 import Ether
from scapy.sendrecv import sniff
from scapy.utils import *

from tools import *

platform, netcards = get_nic_list()
flush_time = 2000
if platform == 'Windows':
    keys = list(netcards.keys())
elif platform == 'Linux':
    keys = list(netcards)


# arp字典
arp_dict = {
    1: "who-has",
    2: "is-at",
    3: "RARP-req",
    4: "RARP-rep",
    5: "Dyn-RARP-req",
    6: "Dyn-RAR-rep",
    7: "Dyn-RARP-err",
    8: "InARP-req",
    9: "InARP-rep"
    }
# icmpv6 code字典
icmpv6_code = {
    1: {
        0: "No route to destination",
        1: "Communication with destination administratively prohibited",
        2: "Beyond scope of source address",
        3: "Address unreachable",
        4: "Port unreachable"
    },
    3: {
        0: "hop limit exceeded in transit",
        1: "fragment reassembly time exceeded"
    },
    4: {
        0: "erroneous header field encountered",
        1: "unrecognized Next Header type encountered",
        2: "unrecognized IPv6 option encountered",
        3: "first fragment has incomplete header chain"
    },
    }
# 端口字典
ports = {
    53: "DNS",
    1900: "SSDP",
    20: "FTP_Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    110: "POP3",
    123: "NTP"
    }

https_version = {
    769: "TLSv1.0",
    770: "TLSv1.1",
    771: "TLSv1.2",
    772: "TLSv1.3"
    }

# 停止抓包的线程
stop_capturing_thread = Event()

# 数据包背景颜色字典
color_dict = {
    "TCP": "#eaff56",
    "TCPv6": "#eaff56",
    "UDP": "#daeeff",
    "UDPv6": "#daeeff",
    "HTTP": "#ffb3ff",
    "HTTPv6": "#ffb3ff",
    "Telnet": "#8562e9",
    "FTP": "#b3664c",
    "FTPv6": "#b3664c",
    "FTP_Data": "#8470c2",
    "DHCP": "#a4c1a4",
    "DHCPv6": "#a4c1a4",
    "ARP": "#faf0d7",
    "SMTP": "#7fb3b3",
    "SMTPv6": "#7fb3b3",
    "TFTP": "#aa8d8d",
    "TFTPv6": "#aa8d8d",
    "TLSv1.0": "#ff6699",
    "TLSv1.1": "#c797ff",
    "TLSv1.2": "#bfbdff",
    "TLSv1.3": "#a14545",
    "POP3": "#c1a4ba",
    "DNS": "#00ffff",
    "DNSv6": "#00ffff",
    "SSH": "#4c98b3",
    "SSHv6": "#4c98b3",
    "SSDP": "#ffe3e5",
    "SSDPv6": "#ffe3e5",
    "ICMP": "#fce0ff",
    "ICMPv6": "#fce0ff",
    "NTP": "#daeeff",
    "NTPv6": "#daeeff"
}

load_layer("tls")
load_layer("http")

class Core():
    # 包编号
    packet_id = 1
    # 开始标志
    start_flag = False
    # 暂停标志
    pause_flag = False
    # 停止标志
    stop_flag = False
    # 保存标志
    save_flag = False
    # 开始时间戳
    start_timestamp = 0.0
    # 临时文件
    temp_file = None
    # 计数器
    counter = {
        "ipv4": 0,
        "ipv6": 0,
        "tcp": 0, 
        "udp": 0,
        "icmp": 0,
        "arp": 0
        }

    def __init__(self, mainwindow):
        """
        初始化, 若不设置netcard则为捕捉所有网卡的数据包
        :parma mainwindow: 传入主窗口
        """
        self.main_window = mainwindow
        temp = NamedTemporaryFile(
            suffix=".pcap",
            prefix=str(int(time.time())),
            delete=False
            )
        self.temp_file = temp.name
        temp.close()

    def handle_packet(self, packet, writer):
        """
        处理抓到的数据包
        :parma packet: 需要处理分类的包
        """
        unkown = False
        try:
            # 如果暂停，则不对列表进行更新操作
            if not self.pause_flag and packet.name == "Ethernet":
                protocol = None
                if self.packet_id == 1:
                    self.start_timestamp = packet.time
                packet_time = packet.time - self.start_timestamp
                # 网络层
                net = packet.payload
                network_layer = net.name
                version_add = ""
                # IPv4
                if network_layer == "IP":
                    source = packet[IP].src
                    destination = packet[IP].dst
                    self.counter["ipv4"] += 1
                # IPv6
                elif network_layer == "IPv6":
                    source = packet[IPv6].src
                    destination = packet[IPv6].dst
                    version_add = "v6"
                    self.counter["ipv6"] += 1
                # ARP
                elif network_layer == "ARP":
                    self.counter["arp"] += 1
                    protocol = network_layer
                    source = packet[Ether].src
                    destination = packet[Ether].dst
                    if destination == "ff:ff:ff:ff:ff:ff":
                        destination = "Broadcast"
                else:
                    try:
                        protocol = network_layer
                        unkown = True
                    except:
                        # 其他协议不处理
                        return
                # 传输层
                if network_layer != "ARP" and not unkown:
                    # 传输层
                    trans = net.payload
                    protocol = trans.name
                    sport = None
                    dport = None
                    if protocol == "TCP":
                        sport = packet[TCP].sport
                        dport = packet[TCP].dport
                        protocol += version_add
                        self.counter["tcp"] += 1
                    elif protocol == "UDP":
                        sport = packet[UDP].sport
                        dport = packet[UDP].dport
                        protocol += version_add
                        self.counter["udp"] += 1
                    elif len(protocol) >= 4 and protocol[0:4] == "ICMP":
                        protocol = "ICMP" + version_add
                        self.counter["icmp"] += 1
                    else:
                        return
                    if trans.haslayer(HTTPRequest) or trans.haslayer(HTTPResponse):
                        protocol = "HTTP" + version_add
                    elif trans.haslayer(TLS):
                        protocol = https_version[trans[TLS].version]
                    
                    if sport and dport:
                        if sport in ports:
                            protocol = ports[sport] + version_add
                        elif dport in ports:
                            protocol = ports[dport] + version_add
                item = QTreeWidgetItem(self.main_window.packet_tree)
                # 根据协议类型不同设置颜色
                try:
                    color = color_dict[protocol]
                except:
                    color = "#ff80c0"
                for i in range(7):
                    item.setBackground(i, QBrush(QColor(color)))
                # 添加行内容
                item.setData(0, Qt.DisplayRole, self.packet_id)
                item.setText(1, f"{packet_time:.6f}")
                item.setText(2, source)
                item.setText(3, destination)
                item.setText(4, protocol)
                item.setData(5, Qt.DisplayRole, len(packet))
                item.setText(6, packet.summary())
                # 时间栏右对齐，为了格式化后不影响排序
                # item.setTextAlignment(1, Qt.AlignRight)
                self.packet_id += 1
                if writer:
                    writer.write(packet)
        except:
            pass

    def on_click_item(self, this_id):
        """
        处理点击列表中的项
        :parma this_id: 包对应的packet_id，在packet_list里获取该packet
        """
        try:
            if not this_id or this_id < 1:
                return
            pre_pkt_time, packet = self.read_packet(this_id - 1)
            # 详细信息列表, 用于添加进GUI
            first_return = []
            second_return = []
            ether_fir, ether_sec = self.ether_layer_info(
                this_id,
                pre_pkt_time,
                packet
                )
            first_return.append(ether_fir)
            second_return.append(ether_sec)
            first_temp, second_temp = self.get_next_layer(packet)
            first_return += first_temp
            second_return += second_temp
            temp_trans = packet.payload.payload
            # 添加 HTTP 报文信息到二维列表中
            if temp_trans.haslayer(HTTPRequest) or temp_trans.haslayer(HTTPResponse):
                first_return.append("Hypertext Transfer Protocol")
                fir_raw, http_addition = self.http_layer_info(temp_trans[HTTP])
                if fir_raw:
                    first_return.append(fir_raw)
                else:
                    http_addition.pop()
                second_return.extend(http_addition)
            
            # 添加 HTTPS 报文信息到二维列表中
            # dump=True 将视图返回为字符串而不是打印
            elif temp_trans.haslayer(TLS):
                first_return.append("Transport Layer Security")
                second_return.append([temp_trans[TLS].show(dump=True)])
            elif temp_trans.haslayer(SSLv2):
                ssl_ver = temp_trans.payload.name
                first_return.append(f"Secure Sockets Layer ({ssl_ver})")
                second_return.append([temp_trans.payload.show(dump=True)])
            # 添加 DNS 报文信息到二维列表中
            elif temp_trans.haslayer(DNS):
                fir_temp, sec_temp = self.dns_layer_info(temp_trans)
                first_return.append(fir_temp)
                second_return.append(sec_temp)
        except:
            pass
        # dump=True 将hexdump返回而不是打印
        return first_return, second_return, hexdump(packet, dump=True)

    def ether_layer_info(self, th_id, ppt, pkt):
        # 第一层: Frame
        first_layer = []
        # on wire的长度
        packet_wirelen = f"{pkt.wirelen} bytes ({pkt.wirelen << 3} bits)"
        # 实际抓到的长度
        packet_capturedlen = f"{len(pkt)} bytes ({len(pkt) << 3} bits)"
        frame = f"Frame {th_id}: {packet_wirelen} on wire, {packet_capturedlen} captured"
        # 抓包的时间
        first_layer.append(
            f"Arrival Time: {time_to_formal(pkt.time)} 中国标准时间"
            )
        first_layer.append(
            f"Epoch Time: {pkt.time} seconds"
            )
        first_layer.append(
            f"[Time delta from previous captured frame: {pkt.time - ppt} seconds]"
            )
        # 新抓到包 pkt.time 为float型
        # 从 pacp 文件中读取的包的 pkt.time 为 decimal.Decimal 型
        # read_packet 处理后的数据包 pkt.time 为float型
        try:
            first_layer.append(
                f"[Time since reference or first frame: {pkt.time - self.start_timestamp} seconds]"
                )
        except:
            first_layer.append(
                f"[Time since reference or first frame: {Decimal(str(pkt.time)) - self.start_timestamp} seconds]"
                )
        first_layer.append(f"Frame Number: {th_id}")
        first_layer.append(f"Frame Length: {packet_wirelen}")
        first_layer.append(f"Capture Length: {packet_capturedlen}")
        
        return frame, first_layer

    def get_next_layer(self, packet):
        """
        递归处理下一层信息
        :parma packet: 处理来自上一层packet的payload
        """
        # 第二层: Ethernet
        first_return = []
        second_return = []
        next_layer = []
        def set_or_not_set(temp_string, attr):
            ans = "Set (1)" if attr == 1 else "Not set (0)"
            return temp_string + ans

        try:
            protocol = packet.name
            packet_class = packet.__class__
            if protocol == "NoPayload":
                return first_return, second_return
            elif protocol == "Ethernet":
                ether_src = packet[packet_class].src
                ether_dst = packet[packet_class].dst
                if ether_dst == "ff:ff:ff:ff:ff:ff":
                    ether_dst = "Broadcast (ff:ff:ff:ff:ff:ff)"
                ethernet = f"Ethernet II, Src: {ether_src}, Dst: {ether_dst}"
                first_return.append(ethernet)
                next_layer.append(f"Source: {ether_src}")
                next_layer.append(f"Destination: {ether_dst}")
                network_layer = packet.payload.name
                if network_layer == "IP":
                    network_layer += "v4"
                ether_proto = (
                    f"Type: {network_layer} ({hex(packet[packet_class].type)})"
                    )
                next_layer.append(ether_proto)
            # 第三层: 网络层
            # IPv4
            elif protocol == "IP" or protocol == "IP in ICMP":
                protocol += "v4"
                ip_src = packet[packet_class].src
                ip_dst = packet[packet_class].dst
                network = f"Internet Protocol Version 4, Src: {ip_src}, Dst: {ip_dst}"
                first_return.append(network)
                next_layer.append(
                    f"Version: {packet[packet_class].version}"
                    )
                next_layer.append(
                    f"Header Length: {packet[packet_class].ihl << 2} bytes ({packet[packet_class].ihl})"
                    )
                next_layer.append(
                    f"Differentiated Services Field: {hex(packet[packet_class].tos)}"
                    )
                next_layer.append(
                    f"Total Length: {packet[packet_class].len}"
                    )
                next_layer.append(
                    f"Identification: {hex(packet[packet_class].id)} ({packet[packet_class].id})"
                    )
                next_layer.append(
                    f"Flags: {packet[packet_class].flags} ({hex(packet[packet_class].flags.value)})"
                    )
                next_layer.append(
                    f"Fragment offset: {packet[packet_class].frag}"
                    )
                next_layer.append(
                    f"Time to live: {packet[packet_class].ttl}"
                    )
                next_protocol = packet.payload.name
                if next_protocol == "IP":
                    next_protocol += "v4"
                next_layer.append(
                    f"Protocol: {next_protocol} ({packet[packet_class].proto})"
                    )
                ip_chksum = packet[packet_class].chksum
                ip_check = packet_class(raw(packet[packet_class])).chksum
                next_layer.append(
                    f"Header checksum: {hex(ip_chksum)}"
                    )
                next_layer.append(
                    "[Header checksum status: " +
                    "Correct]" if ip_check == ip_chksum else "Incorrect]"
                    )
                next_layer.append(
                    f"Source: {ip_src}"
                    )
                next_layer.append(
                    f"Destination: {ip_dst}"
                    )
            # IPv6
            elif protocol == "IPv6" or protocol == "IPv6 in ICMPv6":
                ipv6_src = packet[packet_class].src
                ipv6_dst = packet[packet_class].dst
                network = (
                    f"Internet Protocol Version 6, Src: {ipv6_src}, Dst: {ipv6_dst}"
                    )
                first_return.append(network)
                next_layer.append(
                    f"Version: {packet[packet_class].version}"
                    )
                next_layer.append(
                    f"Traffice Class: {hex(packet[packet_class].tc)}"
                    )
                next_layer.append(
                    f"Flow Label: {hex(packet[packet_class].fl)}"
                    )
                next_layer.append(
                    f"Payload Length: {packet[packet_class].plen}"
                    )
                next_protocol = packet.payload.name
                if next_protocol == "IP":
                    next_protocol += "v4"
                next_layer.append(
                    f"Next Header: {next_protocol} ({packet[packet_class].nh})"
                    )
                next_layer.append(
                    f"Hop Limit: {packet[packet_class].hlim}"
                    )
                next_layer.append(
                    f"Source: {ipv6_src}"
                    )
                next_layer.append(
                    f"Destination: {ipv6_dst}"
                    )
            elif protocol == "ARP":
                arp_op = packet[packet_class].op
                network = "Address Resolution Protocol "
                if arp_op in arp_dict:
                    network += f"({arp_dict[arp_op]})"
                first_return.append(network)
                next_layer.append(
                    f"Hardware type: {packet[packet_class].hwtype}"
                    )
                ptype = packet[packet_class].ptype
                temp_str = f"Protocol type: {hex(packet[packet_class].ptype)}"
                if ptype == 0x0800:
                    temp_str += " (IPv4)"
                elif ptype == 0x86DD:
                    temp_str += " (IPv6)"
                next_layer.append(temp_str)
                next_layer.append(
                    f"Hardware size: {packet[packet_class].hwlen}"
                    )
                next_layer.append(
                    f"Protocol size: {packet[packet_class].plen}"
                    )
                temp_str = f"Opcode: {arp_op}"
                if arp_op in arp_dict:
                    temp_str += f" ({arp_dict[arp_op]})"
                next_layer.append(temp_str)
                next_layer.append(
                    f"Sender MAC address: {packet[packet_class].hwsrc}"
                    )
                next_layer.append(
                    f"Sender IP address: {packet[packet_class].psrc}"
                    )
                next_layer.append(
                    f"Target MAC address: {packet[packet_class].hwdst}"
                    )
                next_layer.append(
                    f"Target IP address: {packet[packet_class].pdst}"
                    )
            # 第四层: 传输层
            elif protocol == "TCP" or protocol == "TCP in ICMP":
                src_port = packet[packet_class].sport
                dst_port = packet[packet_class].dport
                payload_length = len(packet.payload)
                transport = (
                    f"Transmission Control Protocol, Src Port: {src_port}, Dst Port: {dst_port}, Len: {payload_length}"
                    )
                first_return.append(transport)
                next_layer.append(
                    f"Source Port: {src_port}"
                    )
                next_layer.append(
                    f"Destination Port: {dst_port}"
                    )
                next_layer.append(
                    f"Sequence number: {packet[packet_class].seq}"
                    )
                next_layer.append(
                    f"Acknowledgment number: {packet[packet_class].ack}"
                    )
                tcp_head_length = packet[packet_class].dataofs
                next_layer.append(
                    f"Header Length: {tcp_head_length << 2} bytes ({tcp_head_length})"
                    )
                next_layer.append(
                    f"Flags: {hex(packet[packet_class].flags.value)} ({packet[packet_class].flags})"
                    )
                next_layer.append(
                    f"Window size value: {packet[packet_class].window}"
                    )
                tcp_chksum = packet[packet_class].chksum
                tcp_check = packet_class(raw(packet[packet_class])).chksum
                next_layer.append(
                    f"Checksum: {hex(tcp_chksum)}"
                    )
                next_layer.append(
                    "[Checksum status: " + "Correct]" if tcp_check == tcp_chksum else "Incorrect]"
                    )
                next_layer.append(
                    f"Urgent pointer: {packet[packet_class].urgptr}"
                    )
                options = packet[packet_class].options
                options_length = len(options) << 1
                if options_length > 0:
                    string = f"Options: ({options_length} bytes)"
                    for item in options:
                        string += f", {item[0]}: {str(item[1])}"
                    next_layer.append(string)
                next_layer.append(
                    f"TCP payload: {payload_length} bytes"
                    )
            elif protocol == "UDP" or protocol == "UDP in ICMP":
                src_port = packet[packet_class].sport
                dst_port = packet[packet_class].dport
                length = packet[packet_class].len
                transport = (
                    f"User Datagram Protocol, Src Port: {src_port}, Dst Port: {dst_port}"
                    )
                first_return.append(transport)
                next_layer.append(
                    f"Source Port: {src_port}"
                    )
                next_layer.append(
                    f"Destination Port: {dst_port}"
                    )
                next_layer.append(
                    f"Length: {length}"
                    )
                udp_chksum = packet[packet_class].chksum
                udp_check = packet_class(raw(packet[packet_class])).chksum
                next_layer.append(
                    f"Chksum: {hex(udp_chksum)}"
                    )
                next_layer.append(
                    "[Checksum status: " +
                    "Correct]" if udp_check == udp_chksum else "Incorrect]"
                    )
                length = len(packet[packet_class].payload)
                # Have payload
                if length > 0:
                    second_return.append(next_layer.copy())
                    next_layer.clear()
                    payload = bytes(packet[packet_class].payload)
                    # SSDP
                    if src_port == 1900 or dst_port == 1900:
                        first_return.append(
                            "Simple Service Discovery Protocol"
                            )
                        payload = bytes.decode(payload).split('\r\n')
                        for text in payload:
                            if text:
                                next_layer.append(text)
                    # Raw
                    else:
                        first_return.append(
                            f"Data ({length} bytes)"
                            )
                        next_layer.append(
                            f"Data: {payload.hex()}"
                            )
                        next_layer.append(
                            f"[Length: {length}]"
                            )
            elif protocol == "ICMP" or protocol == "ICMP in ICMP":
                transport = "Internet Control Message Protocol"
                first_return.append(transport)
                packet_type = packet[packet_class].type
                temp_str = f"Type: {packet_type}"
                if packet_type in icmptypes:
                    temp_str += f" ({icmptypes[packet_type]})"
                next_layer.append(temp_str)
                packet_code = packet[packet_class].code
                temp_str = f"Code: {packet_code}"
                if packet_type in icmpcodes:
                    if packet_code in icmpcodes[packet_type]:
                        temp_str += f" ({icmpcodes[packet_type][packet_code]})"
                next_layer.append(temp_str)
                icmp_chksum = packet[packet_class].chksum
                icmp_check = packet_class(raw(packet[packet_class])).chksum
                next_layer.append(
                    f"Checksum: {hex(icmp_chksum)}"
                    )
                next_layer.append(
                    "[Checksum status: " +
                    "Correct]" if icmp_check == icmp_chksum else "Incorrect]"
                    )
                if packet_type == 0 or packet_type == 8 or protocol == "ICMP in ICMP":
                    next_layer.append(
                        f"Identifier: {packet[packet_class].id} ({hex(packet[packet_class].id)})"
                        )
                    next_layer.append(
                        f"Sequence number: {packet[packet_class].seq} ({hex(packet[packet_class].seq)})"
                        )
                    data_length = len(packet.payload)
                    if data_length > 0:
                        next_layer.append(
                            f"Data ({data_length} bytes): {packet[packet_class].load.hex()}"
                            )
            elif len(protocol) >= 6 and protocol[0:6] == "ICMPv6":
                if protocol.lower().find("option") == -1:
                    transport = "Internet Control Message Protocol v6"
                    first_return.append(transport)
                    proto_type = packet[packet_class].type
                    temp_str = f"Type: {proto_type}"
                    if proto_type in icmp6types:
                        temp_str += f" ({icmp6types[proto_type]})"
                    next_layer.append(temp_str)
                    packet_code = packet[packet_class].code
                    temp_str = f"Code: {packet_code}"
                    if proto_type in icmpv6_code:
                        if packet_code in icmpv6_code[proto_type]:
                            temp_str += f" ({icmpv6_code[proto_type][packet_code]})"
                    next_layer.append(temp_str)
                    icmpv6_cksum = packet[packet_class].cksum
                    icmpv6_check = packet_class(raw(packet[packet_class])).cksum
                    next_layer.append(
                        f"Checksum: {hex(icmpv6_cksum)}"
                        )
                    next_layer.append(
                        "[Checksum status: " +
                        "Correct]" if icmpv6_check == icmpv6_cksum else "Incorrect]"
                        )
                    if proto_type == "Echo Request" or proto_type == "Echo Reply":
                        next_layer.append(
                            f"Identifier: {packet[packet_class].id} ({hex(packet[packet_class].id)})"
                            )
                        next_layer.append(
                            f"Sequence number: {packet[packet_class].seq} ({hex(packet[packet_class].seq)})"
                            )
                        data_length = packet[packet_class].plen - 8
                        if data_length > 0:
                            next_layer.append(
                                f"Data ({data_length} bytes): {packet[packet_class].load.hex()}"
                                )
                    elif proto_type == "Neighbor Advertisement":
                        temp_ans = set_or_not_set("Router: ", packet[packet_class].R)
                        next_layer.append(temp_ans)

                        temp_ans = set_or_not_set("Solicited: ", packet[packet_class].S)
                        next_layer.append(temp_ans)

                        temp_ans = set_or_not_set("Override: ", packet[packet_class].O)
                        next_layer.append(temp_ans)

                        next_layer.append(
                            f"Reserved: {packet[packet_class].res}"
                            )
                        next_layer.append(
                            f"Target Address: {packet[packet_class].tgt}"
                            )
                    elif proto_type == "Neighbor Solicitation":
                        next_layer.append(
                            f"Reserved: {packet[packet_class].res}"
                            )
                        next_layer.append(
                            f"Target Address: {packet[packet_class].tgt}"
                            )
                    elif proto_type == "Router Solicitation":
                        next_layer.append(
                            f"Reserved: {packet[packet_class].res}"
                            )
                    elif proto_type == "Router Advertisement":
                        next_layer.append(
                            f"Cur hop limit: {packet[packet_class].chlim}"
                            )

                        temp_ans = set_or_not_set(
                            "Managed address configuration: ",
                            packet[packet_class].M
                            )
                        next_layer.append(temp_ans)

                        temp_ans = set_or_not_set(
                            "Other configuration: ",
                            packet[packet_class].O
                            )
                        next_layer.append(temp_ans)

                        temp_ans = set_or_not_set(
                            "Home Agent: ",
                            packet[packet_class].H
                            )
                        next_layer.append(temp_ans)

                        temp_str = f"Preference: {packet[packet_class].prf}"
                        next_layer.append(temp_str)

                        temp_ans = set_or_not_set(
                            "Proxy: ",
                            packet[packet_class].P
                            )
                        next_layer.append(temp_ans)

                        next_layer.append(
                            f"Reserved: {packet[packet_class].res}"
                            )
                        next_layer.append(
                            f"Router lifetime (s): {packet[packet_class].routerlifetime}"
                            )
                        next_layer.append(
                            f"Reachable time (ms): {packet[packet_class].reachabletime}"
                            )
                        next_layer.append(
                            f"Retrans timer (ms): {packet[packet_class].retranstimer}"
                            )
                    elif proto_type == "Destination Unreachable":
                        next_layer.append(
                            f"Length: {packet[packet_class].length} ({hex(packet[packet_class].length)})"
                        )
                        next_layer.append(
                            f"Unused: {packet[packet_class].unused}"
                            )
                    elif proto_type == "Packet too big":
                        next_layer.append(
                            f"MTU: {packet[packet_class].mtu}"
                            )
                    elif proto_type == "Parameter problem":
                        next_layer.append(
                            f"PTR: {packet[packet_class].ptr}"
                            )
                    elif proto_type == "Time exceeded":
                        next_layer.append(
                            f"Length: {packet[packet_class].length} ({hex(packet[packet_class].length)})"
                        )
                        next_layer.append(
                            f"Unused: {packet[packet_class].unused}"
                            )
                else:
                    # ICMPv6 Option
                    transport = "ICMPv6 Option ("
                    proto_type = packet[packet_class].type
                    # Source Link-Layer or Destination Link-Layer
                    if proto_type == 1 or proto_type == 2:
                        address = packet[packet_class].lladdr
                        if proto_type == 1:
                            transport += f"Source Link-Layer Address: {address})"
                            proto_type = "Type: Source Link-Layer Address (1)"
                        else:
                            transport += f"Destination Link-Layer Address: {address})"
                            proto_type = "Type: Destination Link-Layer Address (2)"
                        first_return.append(transport)
                        next_layer.append(proto_type)
                        length = packet[packet_class].len
                        next_layer.append(
                            f"Length: {length} ({length << 3} bytes)"
                            )
                        next_layer.append(
                            f"Link-Layer Address: {address}"
                            )
                    # Prefix Information
                    elif proto_type == 3:
                        packet_prefix = packet[packet_class].prefix
                        transport += f"Prefix Information: {packet_prefix})"
                        proto_type = "Type: Prefix Information (3)"
                        first_return.append(transport)
                        next_layer.append(proto_type)
                        length = packet[packet_class].len
                        next_layer.append(
                            f"Length: {length} ({length << 3} bytes)"
                            )
                        next_layer.append(
                            f"Prefix Length: {packet[packet_class].prefixlen}"
                            )
                        set_str = "Set (1)"
                        not_set_str = "Not set (0)"
                        next_layer.append(
                            f"On-link flag (L): {set_str if packet[packet_class].L == 1 else not_set_str}"
                            )
                        next_layer.append(
                            f"Autonomous address-configuration flag (A): {set_str if packet[packet_class].A == 1 else not_set_str}"
                            )
                        next_layer.append(
                            f"Router address flag(R): {set_str if packet[packet_class].R == 1 else not_set_str}"
                            )
                        next_layer.append(
                            f"Valid Lifetime: {packet[packet_class].validlifetime}"
                            )
                        next_layer.append(
                            f"Preferred Lifetime: {packet[packet_class].preferredlifetime}"
                            )
                        next_layer.append(
                            f"Reserverd: {packet[packet_class].res2}"
                            )
                        next_layer.append(
                            f"Prefix: {packet_prefix}"
                            )
                    # MTU
                    elif proto_type == 5:
                        packet_mtu = packet[packet_class].mtu
                        transport += f"MTU: {packet_mtu})"
                        proto_type = "Type: MTU (5)"
                        first_return.append(transport)
                        next_layer.append(proto_type)
                        length = packet[packet_class].len
                        next_layer.append(
                            f"Length: {length} ({length << 3} bytes)"
                            )
                        next_layer.append(
                            f"Reserverd: {packet[packet_class].res}"
                            )
                        next_layer.append(
                            f"MTU: {packet_mtu}"
                            )
                    else:
                        # 不识别，直接返回
                        return first_return, second_return

            if next_layer:
                second_return.append(next_layer)
            first_temp, second_temp = self.get_next_layer(packet.payload)
            first_return += first_temp
            second_return += second_temp
        except:
            # 未知数据包
            first_return.clear()
            second_return.clear()
        return first_return, second_return

    def http_layer_info(self, pkt):
        http_layer = []
        raw_data = None
        is_raw_not = "Line-based text data"
        for key, val in pkt.payload.fields.items():
            if val:
                try:
                    val = val.decode()
                except:
                    pass
                http_layer.append(f"{key.replace('_', '-')}: {val}")
        # Raw 层数据
        try:
            pay = pkt[Raw].load.decode().strip()
            raw_data = [each for each in pay.split("\r\n")]
        except:
            is_raw_not = ""
        return is_raw_not, [http_layer, raw_data]

    def dns_layer_info(self, pkt):
        dns_dict = pkt[DNS].fields
        dns_layer = []
        fir_str = "Domain Name System " + (
            "(query)" if dns_dict['qr'] == 0 else "(response)"
            )
        dns_layer.append(
            f"Transaction ID: {hex(dns_dict['id'])}"
            )
        dns_layer.append(
            f"Opcode: Standard query ({dns_dict['opcode']})"
            )
        dns_layer.append(
            f"Truncated: Message is not truncated"
            )    # dns_dict['tc']
        dns_layer.append(
            f"Recursion desired: Do query recursively"
            )    # dns_dict['rd']
        dns_layer.append(
            f"Z: reserved ({dns_dict['z']})"
            )
        qdns_dict = pkt[DNSQR].fields
        dns_name = qdns_dict['qname'].decode()
        if dns_name.endswith("."):
            dns_name = dns_name.rstrip(".")
        dns_layer.append("Queries：")
        dns_layer.append(
            f"    Name: {dns_name}"
            )
        dns_layer.append(
            f"    [Name Length: {len(dns_name)}]"
            )
        dns_layer.append(
            f"    Type: A (Host Address) ({qdns_dict['qtype']})"
            )
        dns_layer.append(
            f"    Class: IN ({hex(qdns_dict['qclass'])})"
            )
        try:
            rdns_dict = pkt[DNSRR].fields
            dns_layer.append("Answers：")
            dns_layer.append(
                f"    Name: {rdns_dict['rrname'].decode()}"
                )
            dns_layer.append(
                f"    Type: A (Host Address) ({rdns_dict['type']})"
                )
            dns_layer.append(
                f"    Class: IN ({hex(rdns_dict['rclass'])})"
                )
            dns_layer.append(
                f"    Time to live: {rdns_dict['ttl']} seconds"
                )
            dns_layer.append(
                f"    Data length: {rdns_dict['rdlen']}"
                )
            dns_layer.append(
                f"    Address: {rdns_dict['rdata'].decode()}"
                )
        except:
            pass
        return fir_str, dns_layer

    def flow_count(self, netcard=None):
        """
        刷新下载速度、上传速度、发包速度和收包速度
        """
        if netcard and platform == 'Windows':
            # 反转键值对
            my_dict = dict(zip(netcards.values(), netcards.keys()))
            netcard = my_dict[netcard]
        while not stop_capturing_thread.is_set():
            recv_bytes, sent_bytes, recv_pak, sent_pak = get_formal_rate(
                get_rate(netcard))
            if not self.pause_flag:
                self.main_window.cpCounter.setText(
                    '已捕获分组：' + str(self.packet_id - 1)
                    )
                self.main_window.downSpeed.setText(
                    '下载速度：' + recv_bytes
                    )
                self.main_window.upSpeed.setText(
                    '上传速度：' + sent_bytes
                    )
                self.main_window.recvSpeed.setText(
                    '收包速度：' + recv_pak
                    )
                self.main_window.sendSpeed.setText(
                    '发包速度：' + sent_pak
                    )
        self.main_window.cpCounter.setText(
            '已捕获分组：' + str(self.packet_id - 1)
            )
        self.main_window.downSpeed.setText(
            '下载速度：0 B/s'
            )
        self.main_window.upSpeed.setText(
            '上传速度：0 B/s'
            )
        self.main_window.recvSpeed.setText(
            '收包速度：0 pak/s'
            )
        self.main_window.sendSpeed.setText(
            '发包速度：0 pak/s'
            )

    def capture_packet(self, netcard, filters):
        """
        抓取数据包
        """
        stop_capturing_thread.clear()
        # 第一个参数可以传入文件对象或者文件名字
        writer = PcapWriter(self.temp_file, append=True, sync=True)
        Thread(
            target=self.flow_count,
            daemon=True,
            args=(netcard, )
            ).start()
        # sniff中的store=False 表示不保存在内存中，防止内存使用过高
        try:
            sniff(iface=netcard,
                prn=(lambda x: self.handle_packet(x, writer)),
                filter=filters,
                stop_filter=(lambda x: stop_capturing_thread.is_set()),
                store=False)
        except:
            QMessageBox.warning(None,
            "警告",
            "！未在此计算机上检测到 Npcap！！\n"
            "！！软件将无法正常运行！！\n\n"
            "详情请查看 帮助——使用文档")
        # 执行完成关闭writer
        writer.close()

    def start_capture(self, netcard=None, filters=None):
        """
        开启新线程进行抓包
        :parma netcard: 选择的网卡, 不指定默认全选
        :parma filters: 过滤器条件
        """
        # 如果已开始抓包，则不能进行操作
        if self.start_flag:
            return
        # 如果已经停止且未保存数据包，则提示是否保存数据包
        if self.stop_flag:
            if not self.save_flag and self.packet_id > 1:
                result = QMessageBox.question(
                    None,
                    "提示",
                    "是否保存已抓取的数据包？",
                    QMessageBox.Yes,
                    QMessageBox.Cancel,
                )
                if result == QMessageBox.Yes:
                    self.save_captured_to_pcap()
            self.main_window.packet_tree.clear()
            self.main_window.pkt_detailWidget.clear()
            self.main_window.hexBrowser.clear()
            self.stop_flag = False
            self.save_flag = False
            self.pause_flag = False
            self.packet_id = 1
            self.clean_out()
            temp = NamedTemporaryFile(
                suffix=".pcap",
                prefix=str(int(time.time())),
                delete=False
                )
            self.temp_file = temp.name
            temp.close()
        # 如果从暂停开始
        elif self.pause_flag:
            # 继续显示抓到的包显示
            self.pause_flag = False
            self.start_flag = True
            return
        # 开启新线程进行抓包
        Thread(
            target=self.capture_packet,
            daemon=True,
            args=(netcard, filters)
            ).start()
        self.start_flag = True

    def pause_capture(self):
        """
        暂停抓包, 抓包函数仍在进行，只是不更新
        """
        self.pause_flag = True
        self.start_flag = False

    def stop_capture(self):
        """
        停止抓包，关闭线程
        """
        # 通过设置终止线程，停止抓包
        stop_capturing_thread.set()
        self.stop_flag = True
        self.pause_flag = False
        self.start_flag = False

    def restart_capture(self, netcard=None, filters=None):
        """
        重新开始抓包
        """
        self.stop_capture()
        self.start_capture(netcard, filters)

    def save_captured_to_pcap(self):
        """
        将抓到的数据包保存为pcap格式的文件
        """
        if self.packet_id == 1:
            QMessageBox.warning(
                None,
                "警告",
                "没有可保存的数据包！"
                )
            return
        # 选择保存名称
        filename, _ = QFileDialog.getSaveFileName(
            parent=None,
            caption="保存文件",
            directory=getcwd(),
            filter="Pcap Files (*.pcap);;All Files (*)",
        )
        if filename == "":
            QMessageBox.warning(
                None,
                "警告",
                "保存失败！"
                )
            return
        # 如果没有设置后缀名（保险起见，默认是有后缀的）
        if filename.find(".pcap") == -1:
            # 默认文件格式为 pcap
            filename = filename + ".pcap"
        copy(self.temp_file, filename)
        chmod(filename, 0o0400 | 0o0200 | 0o0040 | 0o0004)
        QMessageBox.information(
            None,
            "提示",
            "保存成功！"
            )
        self.save_flag = True

    def open_pcap_file(self):
        """
        打开pcap格式的文件
        """
        if self.stop_flag and not self.save_flag:
            reply = QMessageBox.question(
                None,
                "提示",
                "是否保存已抓取的数据包？",
                QMessageBox.Yes,
                QMessageBox.Cancel,
            )
            if reply == QMessageBox.Yes:
                self.save_captured_to_pcap()
        filename, _ = QFileDialog.getOpenFileName(
            parent=None,
            caption="打开文件",
            directory=getcwd(),
            filter="Pcap Files (*.pcap);;All Files (*)",
        )
        if filename == "":
            return
        self.main_window.packet_tree.clear()
        self.main_window.pkt_detailWidget.clear()
        self.main_window.hexBrowser.clear()
        # 如果没有设置后缀名（保险起见，默认是有后缀的）
        if filename.find(".pcap") == -1:
            # 默认文件格式为 pcap
            filename = filename + ".pcap"
        self.packet_id = 1
        self.main_window.packet_tree.setUpdatesEnabled(False)
        copy(filename, self.temp_file)
        sniff(prn=(lambda x: self.handle_packet(x, None)),
              store=False,
              offline=self.temp_file
              )
        self.main_window.packet_tree.setUpdatesEnabled(True)
        self.stop_flag = True
        self.save_flag = True

    def clean_out(self):
        '''
        清除临时文件
        '''
        try:
            remove(self.temp_file)
        except PermissionError:
            pass
        # 将字典中的值初始化为0
        self.counter = {}.fromkeys(list(self.counter.keys()), 0)

    def get_transport_count(self):
        """
        获取传输层数据包的数量
        """
        the_keys = ['tcp', 'udp', 'icmp', 'arp']
        counter_copy = self.counter.copy()
        return_dict = {}
        for key, value in counter_copy.items():
            if key in the_keys:
                return_dict.update({key: value})
        return return_dict

    def get_network_count(self):
        """
        获取网络层数据包的数量
        """
        the_keys = ['ipv4', 'ipv6']
        counter_copy = self.counter.copy()
        return_dict = {}
        for key, value in counter_copy.items():
            if key in the_keys:
                return_dict.update({key: value})
        return return_dict

    def read_packet(self, location):
        '''
        读取硬盘中的pcap数据
        :parma location: 数据包位置
        :return: 返回参数列表[上一个数据包的时间，数据包]
        '''
        # 数据包时间是否为纳秒级
        nano = False
        # 打开文件
        f = open(self.temp_file, "rb")
        # 获取Pcap格式 magic
        head = f.read(24)
        magic = head[:4]
        linktype = head[20:]
        if magic == b"\xa1\xb2\xc3\xd4":  # big endian
            endian = ">"
            nano = False
        elif magic == b"\xd4\xc3\xb2\xa1":  # little endian
            endian = "<"
            nano = False
        elif magic == b"\xa1\xb2\x3c\x4d":  # big endian, nanosecond-precision
            endian = ">"
            nano = True
        elif magic == b"\x4d\x3c\xb2\xa1":  # little endian, nanosecond-precision
            endian = "<"
            nano = True
        else:
            # 不是pcap文件，弹出错误
            f.close()
            return None
        linktype = struct.unpack(endian + "I", linktype)[0]
        try:
            LLcls = conf.l2types[linktype]
        except KeyError:
            # 未知 LinkType
            LLcls = conf.raw_layer
        sec, usec, caplen = [0, 0, 0]
        for _ in range(location):
            packet_head = f.read(16)
            if len(packet_head) < 16:
                f.close()
                return None
            sec, usec, caplen = struct.unpack(endian + "III", packet_head[:12])
            # f.seek(offset=?, whence=?)
            # :parma offset: 偏移量
            # :parma whence: 开始的位置 0从头开始 1从当前位置 2从文件末尾
            f.seek(caplen, 1)
        previous_time = sec + (0.000000001 if nano else 0.000001) * usec
        packet_head = f.read(16)
        sec, usec, caplen, wirelen = struct.unpack(endian + "IIII", packet_head)
        rp = f.read(caplen)[:0xFFFF]
        if not rp:
            f.close()
            return None
        try:
            p = LLcls(rp)
        except:
            p = conf.raw_layer(rp)
        p.time = sec + (0.000000001 if nano else 0.000001) * usec
        p.wirelen = wirelen
        f.close()
        return previous_time, p
