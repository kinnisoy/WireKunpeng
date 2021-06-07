# -*- coding: utf-8 -*-
from threading import Event, Thread

from psutil import process_iter
from scapy.sendrecv import sniff


class Monitor:
    """
    流量监测
    """
    # 程序使用的端口
    process_ports = []
    # 监测系统是否开始
    start_flag = Event()
    window = None

    def __init__(self, window):
        self.window = window
        self.start_flag.set()

    def getProcessList(self):
        """
        获取有网络连接的进程列表
        """
        process_list = set()
        for proc in process_iter():
            connections = proc.connections()
            if connections:
                process_list.add(proc.name())
        return list(process_list)

    def getProcessConnections(self):
        """
        获取进程使用的网络连接
        """
        process_name = set()
        process_conn = {}
        for proc in process_iter():
            connections = proc.connections()
            if connections:
                process_name.add(proc.name())
                for con in connections:
                    if con.type == 1:  # TCP
                        protocol = 'TCP'
                    elif con.type == 2:  # UDP
                        protocol = 'UDP'
                    # 本地使用的IP及端口
                    laddr = f"{con.laddr[0]}:{con.laddr[1]}"
                    if con.raddr:
                        raddr = f"{con.raddr[0]}:{con.raddr[1]}"
                    elif con.family.value == 2:
                        # IPv4
                        raddr = "0.0.0.0:0"
                    elif con.family.value == 23:
                        # IPv6
                        raddr = "[::]:0"
                    else:
                        raddr = "*:*"
                    info = f"{protocol}\t{con.status}\nLocal: {laddr}\nRemote: {raddr}\n"
                    process_conn.setdefault(
                        proc.name(),
                        set()
                        ).add(info)
        return list(process_name), process_conn

    def getPortList(self, process_name):
        """
        用于刷新某个进程的端口列表
        将端口列表设置到self.process_ports
        """
        ports = set()
        while not self.start_flag.is_set():
            ports.clear()
            for proc in process_iter():
                connections = proc.connections()
                if proc.name() == process_name and connections:
                    for con in connections:
                        if con.laddr:
                            ports.add(con.laddr[1])
                        if con.raddr:
                            ports.add(con.raddr[1])
            if ports:
                self.process_ports = list(ports)
            else:
                # 进程已不存在
                self.window.stop()
                self.window.refresh_process()
                self.window.alert(
                    f"进程 {process_name} 已停止运行!"
                    )

    def getConnections(self, pak):
        """
        获取进程连接信息
        """
        try:
            src = pak.payload.src
            dst = pak.payload.dst
            length = len(pak)
            if src == dst:
                # 相同源地址和目的地址，可能为Land攻击
                self.window.alert(
                    "数据包源地址与目的地址相同, 疑为Land攻击!"
                    )
            elif len(pak.payload) > 65535:
                # IP数据包的最大长度大于64KB(即65535B), 若大于, 则疑为Ping of Death攻击
                self.window.alert(
                    "收到IP数据包长度大于64KB, 疑为Ping拒绝服务攻击!"
                    )
            else:
                tt_trans = pak.payload.payload
                protocol = tt_trans.name
                if protocol != 'ICMP':
                    sport = tt_trans.sport
                    dport = tt_trans.dport
                    info = f"{protocol:7}{src}:{sport} -> {dst}:{dport}{length:>7}"
                    if protocol == 'TCP':
                        info += f'{str(tt_trans.flags):>5}'
                    self.window.conList.addItem(info)
                else:
                    # ICMP报文
                    self.window.conList.addItem(
                        f"{protocol:7}{src} -> {dst}{length:>7}"
                        )
        except:
            pass

    def cap_packet(self):
        """
        设置过滤器, 只接收IP、IPv6、TCP、UDP
        """
        sniff(store=False,
              filter="(tcp or udp or icmp) and (ip6 or ip)",
              prn=lambda x: self.getConnections(x),
              stop_filter=lambda x: self.start_flag.is_set())

    def start(self, process_name):
        """
        开始监视某一进程的流量
        """
        # 开启刷新程序端口的线程
        self.start_flag.clear()
        self.window.conList.clear()
        Thread(
            target=self.getPortList,
            daemon=True,
            args=(process_name, )
            ).start()
        Thread(
            target=self.cap_packet,
            daemon=True
            ).start()

    def stop(self):
        """
        停止监测
        """
        self.start_flag.set()
