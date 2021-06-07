# -*- coding: utf-8 -*-
from os import getcwd
import os
from platform import system
from time import localtime, sleep, strftime
from PySide2.QtWidgets import QFileDialog, QMessageBox, QTreeWidgetItem
from psutil import net_if_addrs, net_io_counters
from wmi import WMI
import shutil

def get_netcard_name():
    '''
    获取网卡MAC和名字对应字典
    {'9C-B6-D0-0E-70-D9': 'WLAN'}
    '''
    netcard_info = {}
    info = net_if_addrs()
    for k, v in info.items():
        for item in v:
            # 除去环路地址
            if item[0] == 2 and item[1] == '127.0.0.1':
                break
            elif item[0] == -1 or item[0] == 17:
                netcard_info.update({item[1]: k})
    return netcard_info

def get_nic_list():
    '''
    Linux返回列表, Windows返回字典
    {'WLAN': 'Intel Wireless-n/a/ac 1535 Wireless Network Adapter'}
    '''
    # 获取系统信息
    system_name = system()
    netcard_name = get_netcard_name()
    if system_name == "Windows":
        wmi_obj = WMI()
        data = {}
        for nic in wmi_obj.Win32_NetworkAdapterConfiguration():
            if nic.MACAddress is not None:
                # 与前面的字典匹配
                mac_address = str(nic.MACAddress).replace(':', '-')
                if mac_address in netcard_name.keys():
                    net_card_name = netcard_name.get(mac_address)
                    nic_name = str(nic.Caption)[11:]
                    data.update({net_card_name: nic_name})
        return system_name, data
    elif system_name == "Linux":
        List = list(netcard_name.values())
        return system_name, List
    else:
        return None

def get_net_flow(net_card):
    """
    返回网卡流量信息
    """
    net_info = net_io_counters(pernic=True).get(net_card)  # 流量统计信息
    # 字节数统计信息
    recv_bytes = net_info.bytes_recv
    sent_bytes = net_info.bytes_sent
    # 数据包统计信息
    recv_pak = net_info.packets_recv
    sent_pak = net_info.packets_sent
    return recv_bytes, sent_bytes, recv_pak, sent_pak

def change_format(count):
    """
    调整字节格式
    """
    if count < 1024:
        return f"{count:.2f} B/s"
    if count < 1048576:
        return f"{count/1024:.2f} KB/s"
    count >>= 10
    if count < 1048576:
        return f"{count/1024:.2f} MB/s"
    count >>= 10
    return f"{count/1024:.2f} GB/s"

def get_rate(net_card):
    """
    计算速率
    """
    net_cards = []
    old = [0, 0, 0, 0]
    new = [0, 0, 0, 0]
    if net_card is None:  # 抓取全部网卡的速度
        net_cards = net_io_counters(pernic=True).keys()
    else:
        net_cards.append(net_card)
    for card in net_cards:
        # 上一秒收集的数据
        info = get_net_flow(card)
        for i in range(4):
            old[i] += info[i]
    sleep(1)
    # 当前所收集的数据
    for card in net_cards:
        # 上一秒收集的数据
        info = get_net_flow(card)
        for i in range(4):
            new[i] += info[i]

    return [new[i]-old[i] for i in range(4)]

def get_formal_rate(info):
    """
    格式化速率显示信息
    """
    recv_bytes = change_format(info[0])  # 每秒接收的字节
    sent_bytes = change_format(info[1])  # 每秒发送的字节
    recv_pak = str(info[2]) + " pak/s"  # 每秒接收的数据包
    sent_pak = str(info[3]) + " pak/s"  # 每秒发送的数据包
    return recv_bytes, sent_bytes, recv_pak, sent_pak

def time_to_formal(time_stamp):
    """
    将时间戳转换为标准时间字符串
    如：2021-05-14 22:45:55.222333
    """
    delta_ms = str(time_stamp - int(time_stamp))
    time_temp = localtime(time_stamp)
    my_time = strftime("%Y-%m-%d %H:%M:%S", time_temp)
    my_time += delta_ms[1:8]
    return my_time

def open_background_file(self):
    filename, _ = QFileDialog.getOpenFileName(
        parent=None,
        caption="打开文件",
        directory=getcwd(),
        filter="photo Files (*.png *.jpg *.jpeg);;All Files (*)",
    )
    if filename == "":
        return
    shutil.copy(filename,os.getcwd()+"/img/bckg_set.png")