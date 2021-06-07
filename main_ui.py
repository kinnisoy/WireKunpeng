# -*- coding: utf-8 -*-
from multiprocessing import Process
from sys import exit

import matplotlib.pyplot as plt
from numpy import arange
from PySide2.QtCore import QMetaObject, QRect, QSize, Qt, QTimer
from PySide2.QtGui import QCloseEvent, QFont, QIcon, QPixmap, QPaintEvent, QPainter
from PySide2.QtWidgets import *

from capture_core import *
from monitor_system import start_monitor
import tools

class Ui_MainWindow(QMainWindow):

    core = None
    timer = None
    monitor = None

    def setupUi(self):
        self.setWindowTitle("WireKunpeng")
        self.resize(1200, 850)

        #设置程序图标
        icon = QIcon()
        icon.addPixmap(
            QPixmap("img/kunpeng.png"),
            QIcon.Normal,
            QIcon.Off
            )
        self.setWindowIcon(icon)
        self.setIconSize(QSize(25, 25))
        #中间布局
        self.centralWidget = QWidget(self)
        self.centralWidget.setStyleSheet("background:transparent;")

        #栅栏布局，使得窗口自适应
        self.gridLayout = QGridLayout(self.centralWidget)
        self.gridLayout.setContentsMargins(0, 0, 0, 0)
        self.gridLayout.setSpacing(6)

        #顶部控件布局
        self.horizontalLayout = QHBoxLayout()
        self.horizontalLayout.setContentsMargins(10, 2, 10, 1)
        self.horizontalLayout.setSpacing(20)

        #三个显示区布局
        self.verticalLayout = QVBoxLayout()
        self.verticalLayout.setContentsMargins(10, 0, 3, 10)
        self.verticalLayout.setSpacing(6)

        # 初始主窗口字体
        font = QFont()
        if platform == 'Windows':
            font.setFamily("Lucida Sans Typewriter")
        elif platform == "Linux":
            font.setFamily("Noto Mono")
        font.setPointSize(11)

        # 数据包显示框
        self.packet_tree = QTreeWidget(self.centralWidget)
        self.packet_tree.setFrameStyle(QFrame.Box | QFrame.Plain)
        self.packet_tree.setAutoScroll(True)

        self.packet_tree.setRootIsDecorated(False)
        self.packet_tree.setFont(font)
        # 固定行高，取消每次刷新所有行，避免更新数据时不流畅
        self.packet_tree.setUniformRowHeights(True)
        # 设置表头
        self.packet_tree.setColumnCount(7)  # 设置表格为7列
        self.packet_tree.headerItem().setText(0, "No.")
        self.packet_tree.headerItem().setText(1, "Time")
        self.packet_tree.headerItem().setText(2, "Source")
        self.packet_tree.headerItem().setText(3, "Destination")
        self.packet_tree.headerItem().setText(4, "Protocol")
        self.packet_tree.headerItem().setText(5, "Length")
        self.packet_tree.headerItem().setText(6, "Info")
        # 设置列宽
        self.packet_tree.setColumnWidth(0, 75)
        self.packet_tree.setColumnWidth(1, 125)
        self.packet_tree.setColumnWidth(2, 180)
        self.packet_tree.setColumnWidth(3, 180)
        self.packet_tree.setColumnWidth(4, 100)
        self.packet_tree.setColumnWidth(5, 85)
        self.packet_tree.setColumnWidth(6, 1000)  # 水平滚动条
        self.packet_tree.setStyleSheet("background: transparent;")
        self.packet_tree.setSortingEnabled(True)
        self.packet_tree.sortItems(0, Qt.AscendingOrder)  # 升序排序

        self.packet_tree.setSelectionBehavior(QTreeWidget.SelectRows)  #设置选中时为整行选中
        self.packet_tree.setSelectionMode(QTreeWidget.SingleSelection)  #设置只能选中一行
        """显示排序图标"""
        self.packet_tree.header().setSortIndicatorShown(True)
        self.packet_tree.clicked.connect(self.packetTable_clicked)

        # 数据包详细内容显示框
        self.pkt_detailWidget = QTreeWidget(self.centralWidget)
        self.pkt_detailWidget.setTextElideMode(Qt.ElideMiddle)
        self.pkt_detailWidget.setStyleSheet("background:transparent;")
        self.pkt_detailWidget.setFont(font)
        self.pkt_detailWidget.setAutoScroll(True)
        self.pkt_detailWidget.header().hide()
        self.pkt_detailWidget.header().setStretchLastSection(True)
        # 设为只有一列
        self.pkt_detailWidget.setColumnCount(1)
        self.pkt_detailWidget.setFrameStyle(QFrame.Box | QFrame.Plain)

        # hex显示区域
        self.hexBrowser = QTextBrowser(self.centralWidget)
        # self.hexBrowser.setText("")
        self.hexBrowser.setFont(font)
        self.hexBrowser.setStyleSheet("background:transparent;")
        self.hexBrowser.setFrameStyle(QFrame.Box | QFrame.Plain)

        # 允许用户通过拖动三个显示框的边界来控制子组件的大小
        self.splitter = QSplitter(Qt.Vertical)
        self.splitter.addWidget(self.packet_tree)
        self.splitter.addWidget(self.pkt_detailWidget)
        self.splitter.addWidget(self.hexBrowser)
        self.verticalLayout.addWidget(self.splitter)
        self.gridLayout.addLayout(self.verticalLayout, 1, 0, 1, 1)

        #过滤器输入框
        self.filterBox = QLineEdit(self.centralWidget)
        self.filterBox.setPlaceholderText("Typewrite a capture filter and restart... ")
        self.filterBox.setStyleSheet("background:white")
        self.filterBox.setFont(font)
        self.horizontalLayout.addWidget(self.filterBox)

        #过滤器按钮
        filterIcon = QIcon()
        filterIcon.addPixmap(
            QPixmap("img/go.png"),
            QIcon.Normal,
            QIcon.Off
            )
        self.filterGoButton = QPushButton(self.centralWidget)
        self.filterGoButton.setText("开始")
        self.filterGoButton.setIcon(filterIcon)
        self.filterGoButton.setIconSize(QSize(20, 20))
        self.filterGoButton.setStyleSheet("background:transparent;color:white")
        self.filterGoButton.clicked.connect(self.start_button_clicked_action)
        self.horizontalLayout.addWidget(self.filterGoButton)

        # 网卡选择框
        self.choose_nicbox = QComboBox(self.centralWidget)
        self.choose_nicbox.setFont(font)
        self.choose_nicbox.setStyleSheet("background:white;color:black")
        self.horizontalLayout.addWidget(self.choose_nicbox)

        self.horizontalLayout.setStretch(0, 8)
        self.horizontalLayout.setStretch(1, 1)
        self.horizontalLayout.setStretch(2, 4)

        self.gridLayout.addLayout(self.horizontalLayout, 0, 0, 1, 1)
        # 初始网卡复选框
        self.choose_nicbox.addItem("All")
        for i in range(len(keys)):
            self.choose_nicbox.addItem(keys[i])

        self.setCentralWidget(self.centralWidget)
        
        # 顶部菜单栏
        self.menuBar = QMenuBar(self)
        self.menuBar.setGeometry(QRect(0, 0, 953, 23))
        self.menuBar.setDefaultUp(True)

        self.fileMenu = QMenu(self.menuBar)
        self.fileMenu.setTitle("文件(F)")

        self.editMenu = QMenu(self.menuBar)
        self.editMenu.setTitle("编辑(E)")

        self.captureMenu = QMenu(self.menuBar)
        self.captureMenu.setTitle("捕获(C)")

        self.analysisMenu = QMenu(self.menuBar)
        self.analysisMenu.setTitle("分析(A)")

        self.statisticMenu = QMenu(self.menuBar)
        self.statisticMenu.setTitle("统计(S)")

        self.helpMenu = QMenu(self.menuBar)
        self.helpMenu.setTitle("帮助(H)")
        self.setMenuBar(self.menuBar)

        # 顶部工具栏
        self.mainToolBar = QToolBar(self)
        self.mainToolBar.setStyleSheet("background: #EDEDED")
        self.mainToolBar.setMaximumHeight(25)
        self.statusBar = QStatusBar(self)
        self.setStatusBar(self.statusBar)
        self.addToolBar(Qt.TopToolBarArea, self.mainToolBar)

        # 字体设置键
        font_set = QAction(self)
        font_set.setText("主窗口字体")
        font_set.triggered.connect(self.font_set_clicked_action)

        #背景设置键
        backgroud_set = QAction(self)
        backgroud_set.setText("主窗口背景")
        backgroud_set.triggered.connect(self.backgroud_set_clicked_action)


        #开始键
        startIcon = QIcon()
        startIcon.addPixmap(
            QPixmap("img/start.png"),
            QIcon.Normal,
            QIcon.Off
            )
        self.start_action = QAction(self)
        self.start_action.setIcon(startIcon)
        self.start_action.setText("开始")
        self.start_action.setShortcut('F1')
        self.start_action.triggered.connect(self.start_button_clicked_action)

        #暂停键
        pauseIcon = QIcon()
        pauseIcon.addPixmap(
            QPixmap("img/pause.png"),
            QIcon.Normal,
            QIcon.Off
            )
        self.pause_action = QAction(self)
        self.pause_action.setIcon(pauseIcon)
        self.pause_action.setText("暂停")
        self.pause_action.setShortcut('F2')
        self.pause_action.setDisabled(True)  # 开始时该按钮不可点击
        self.pause_action.triggered.connect(self.pause_button_clicked_action)

        #停止键
        stopIcon = QIcon()
        stopIcon.addPixmap(
            QPixmap("img/stop.png"),
            QIcon.Normal,
            QIcon.Off
            )
        self.stop_action = QAction(self)
        self.stop_action.setIcon(stopIcon)
        self.stop_action.setText("停止")
        self.stop_action.setShortcut('F3')
        self.stop_action.setDisabled(True)  #开始时该按钮不可点击
        self.stop_action.triggered.connect(self.stop_button_clicked_action)

        #重新开始键
        restartIcon = QIcon()
        restartIcon.addPixmap(
            QPixmap("img/restart.png"),
            QIcon.Normal,
            QIcon.Off
            )
        self.restart_action = QAction(self)
        self.restart_action.setIcon(restartIcon)
        self.restart_action.setText("重新开始")
        self.restart_action.setShortcut('F4')
        self.restart_action.setDisabled(True)  # 开始时该按钮不可点击
        self.restart_action.triggered.connect(self.restart_button_clicked_action)

        # 继续更新键
        updateIcon = QIcon()
        updateIcon.addPixmap(
            QPixmap("img/update.png"),
            QIcon.Normal,
            QIcon.Off
            )
        self.update_action = QAction(self)
        self.update_action.setIcon(updateIcon)
        self.update_action.setText("继续更新")
        self.update_action.setShortcut('F5')
        self.update_action.setDisabled(True)
        self.update_action.triggered.connect(self.update_button_clicked_action)

        # 帮助文档
        readme_action = QAction(self)
        readme_action.setText("使用文档")
        about_action = QAction(self)
        about_action.setText("关于 WireKunpeng")
        readme_action.triggered.connect(self.readme_button_clicked_action)
        about_action.triggered.connect(self.about_button_clicked_action)

        #打开文件键
        openfile_action = QAction(self)
        openfile_action.setText("打开")
        openfile_action.setShortcut("ctrl+O")
        openfile_action.triggered.connect(self.openfile_button_clicked_action)

        #保存文件键
        savefile_action = QAction(self)
        savefile_action.setText("保存")
        savefile_action.setShortcut("ctrl+S")
        savefile_action.triggered.connect(self.savefile_button_clicked_action)

        #退出键
        self.exit_action = QAction(self)
        self.exit_action.setCheckable(False)
        self.exit_action.setText("退出")
        self.exit_action.triggered.connect(self.closeEvent)
        self.exit_action.setShortcut('ctrl+Q')
        self.exit_action.setStatusTip('退出应用程序')

        #流量监测
        self.track_action = QAction(self)
        self.track_action.setText("流量监测")
        self.track_action.setShortcut('F6')
        self.track_action.triggered.connect(self.track_button_clicked_action)

        #IP地址类型统计图
        self.ipStatistics = QAction(self)
        self.ipStatistics.setText("IP地址类型统计")
        self.ipStatistics.triggered.connect(self.ipStatistics_clicked_action)

        #报文类型统计图
        self.msgStatistics = QAction(self)
        self.msgStatistics.setText("报文类型统计")
        self.msgStatistics.triggered.connect(self.msgStatistics_clicked_action)

        # 添加工具栏：开始，暂停，停止，重新开始，继续更新
        self.mainToolBar.addAction(self.start_action)
        self.mainToolBar.addAction(self.pause_action)
        self.mainToolBar.addAction(self.stop_action)
        self.mainToolBar.addAction(self.restart_action)
        self.mainToolBar.addAction(self.update_action)

        self.fileMenu.addAction(openfile_action)
        self.fileMenu.addAction(savefile_action)
        self.fileMenu.addAction(self.exit_action)
        self.fileMenu.showFullScreen()
        # 编辑添加字体和背景
        self.editMenu.addAction(font_set)
        self.editMenu.addAction(backgroud_set)
        #捕获菜单栏添加子菜单
        self.captureMenu.addAction(self.start_action)
        self.captureMenu.addAction(self.pause_action)
        self.captureMenu.addAction(self.stop_action)
        self.captureMenu.addAction(self.restart_action)
        self.captureMenu.addAction(self.update_action)

        self.helpMenu.addAction(readme_action)
        self.helpMenu.addAction(about_action)

        self.analysisMenu.addAction(self.track_action)

        self.statisticMenu.addAction(self.ipStatistics)
        self.statisticMenu.addAction(self.msgStatistics)

        self.menuBar.addAction(self.fileMenu.menuAction())
        self.menuBar.addAction(self.editMenu.menuAction())
        self.menuBar.addAction(self.captureMenu.menuAction())
        self.menuBar.addAction(self.analysisMenu.menuAction())
        self.menuBar.addAction(self.statisticMenu.menuAction())
        self.menuBar.addAction(self.helpMenu.menuAction())

        """
        底部状态栏
        利用self.downSpeed.setText()实时更新状态栏信息
        """
        self.netNic = QLabel('Welcome to WireKunpeng!')
        self.cpCounter = QLabel('已捕获分组：')
        self.recvSpeed = QLabel('收包速度：')
        self.sendSpeed = QLabel('发包速度：')
        self.downSpeed = QLabel('下载速度：')
        self.upSpeed = QLabel('上传速度:')
        self.statusBar.setStyleSheet("background: #EDEDED;")
        # 各个单元空间占比
        self.statusBar.addPermanentWidget(self.netNic, stretch=1)
        self.statusBar.addPermanentWidget(self.cpCounter, stretch=1)
        self.statusBar.addPermanentWidget(self.recvSpeed, stretch=1)
        self.statusBar.addPermanentWidget(self.sendSpeed, stretch=1)
        self.statusBar.addPermanentWidget(self.downSpeed, stretch=1)
        self.statusBar.addPermanentWidget(self.upSpeed, stretch=1)

        QMetaObject.connectSlotsByName(self)
        self.core = Core(self)
        # 设置定时器将抓包列表置底
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.packet_tree.scrollToBottom)
        self.show()

    """绘制背景"""

    def paintEvent(self, a0: QPaintEvent):
        painter = QPainter(self)
        from pathlib import Path
        my_file = Path(os.getcwd()+"/img/bckg_set.png")
        if my_file.exists() and my_file.is_file():
            pixmap = QPixmap("img/bckg_set.png")
            painter.drawPixmap(self.rect(), pixmap)
        else:
            pass


    def closeEvent(self, QCloseEvent):
        """
        窗口关闭事件
        """
        def closeFunc():
            self.core.clean_out()
            if self.monitor and self.monitor.is_alive():
                self.monitor.terminate()
            exit()

        if self.core.start_flag or self.core.pause_flag:
            # 没有停止抓包
            reply = QMessageBox.question(
                self,
                '提示',
                "是否停止捕获，并保存已捕获的分组?\n警告：若不保存，已捕获的分组将会丢失",
                QMessageBox.Save | QMessageBox.Close | QMessageBox.Cancel,
                QMessageBox.Cancel
                )
            if reply == QMessageBox.Cancel:
                QCloseEvent.ignore()
            elif reply == QMessageBox.Close:
                self.core.stop_capture()
                closeFunc()
            elif reply == QMessageBox.Save:
                self.core.stop_capture()
                self.savefile_button_clicked_action()
                closeFunc()
        elif self.core.stop_flag and not self.core.save_flag:
            # 已停止，但没有保存文件
            reply = QMessageBox.question(
                self,
                '提示',
                "是否保存已捕获的分组?\n警告：若不保存，已捕获的分组将会丢失",
                QMessageBox.Save | QMessageBox.Close | QMessageBox.Cancel,
                QMessageBox.Cancel
                )
            if reply == QMessageBox.Cancel:
                QCloseEvent.ignore()
            elif reply == QMessageBox.Save:
                self.savefile_button_clicked_action()
                closeFunc()
            else:
                closeFunc()
        elif self.core.save_flag or not self.core.start_flag:
            # 未工作状态
            reply = QMessageBox.question(
                self,
                '提示',
                "是否退出程序？",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
                )
            if reply == QMessageBox.Yes:
                closeFunc()
            else:
                QCloseEvent.ignore()

    def packetTable_clicked(self):
        """
        数据包视图 数据记录点击事件
        点击列表中一条记录时，在下面的frame框中显示帧的详细信息
        """
        selected_row = self.packet_tree.currentItem().text(0)  #当前选择的编号
        # 表格停止追踪更新
        if selected_row and selected_row.isdigit():
            self.timer.stop()
            self.show_infoTree(int(selected_row))
            if not self.core.pause_flag and not self.core.stop_flag:
                self.update_action.setDisabled(False)

    def show_infoTree(self, selected_row):
        """
        展开帧的详细信息
        """
        # 清空数据包详细内容框
        self.pkt_detailWidget.clear()
        """
           添加树节点
           Item1: 第一层树节点
           Item1_1: 第二层树节点，Item1的子节点
        """
        parentList, childList, hex_dump = self.core.on_click_item(selected_row)
        for i in range(len(parentList)):
            item1 = QTreeWidgetItem(self.pkt_detailWidget)
            item1.setText(0, parentList[i])
            for j in range(len(childList[i])):
                item1_1 = QTreeWidgetItem(item1)
                item1_1.setText(0, childList[i][j])
        self.hexBrowser.setText(hex_dump)

    def get_choose_nic(self):
        """
        获取当前选择的网卡
        """
        card = self.choose_nicbox.currentText()
        self.netNic.setText('当前网卡：' + card)
        if card == 'All':
            temp = None
        elif platform == 'Windows':
            temp = netcards[card]
        elif platform == 'Linux':
            temp = card
        else:
            temp = None
        return temp

    def font_set_clicked_action(self):
        """
        设置字体点击事件
        """
        ok, font = QFontDialog.getFont()
        if ok:
            self.packet_tree.setFont(font)
            self.pkt_detailWidget.setFont(font)
            self.hexBrowser.setFont(font)

    #background_set
    def backgroud_set_clicked_action(self):
        tools.open_background_file(self)
        self.paintEvent(self)

    def start_button_clicked_action(self):
        """
        开始键点击事件
        """
        self.core.start_capture(self.get_choose_nic(), self.filterBox.text())
        """
           点击开始后，过滤器不可编辑，开始按钮、网卡选择框全部设为不可选
           激活暂停、停止键、重新开始键
        """
        self.start_action.setDisabled(True)
        self.filterBox.setEnabled(False)
        self.filterGoButton.setEnabled(False)
        self.choose_nicbox.setEnabled(False)
        self.restart_action.setDisabled(False)
        self.pause_action.setEnabled(True)
        self.stop_action.setEnabled(True)
        self.timer.start(flush_time)

    def pause_button_clicked_action(self):
        """
        暂停事件点击事件
        """
        self.core.pause_capture()
        # 激活开始、停止、重新开始键、过滤器、网卡选择框
        self.start_action.setEnabled(False)
        self.stop_action.setDisabled(False)
        self.restart_action.setDisabled(False)
        self.filterBox.setDisabled(False)
        self.filterGoButton.setDisabled(True)
        self.choose_nicbox.setDisabled(False)
        self.pause_action.setDisabled(True)
        self.update_action.setDisabled(False)
        self.timer.stop()

    def stop_button_clicked_action(self):
        """
        菜单栏停止键点击事件
        """
        self.core.stop_capture()
        # 激活开始键、重新开始键、过滤器、网卡选择框
        self.stop_action.setDisabled(True)
        self.pause_action.setDisabled(True)
        self.start_action.setEnabled(True)
        self.filterBox.setDisabled(False)
        self.filterGoButton.setDisabled(False)
        self.choose_nicbox.setDisabled(False)
        self.update_action.setDisabled(True)
        self.timer.stop()

    def update_button_clicked_action(self):
        """
        继续更新键响应事件
        """
        self.timer.start(flush_time)
        self.update_action.setDisabled(True)
        self.start_button_clicked_action()

    def restart_button_clicked_action(self):
        """
        重新开始键响应事件
        """
        # 重新开始清空面板内容
        self.timer.stop()
        self.core.restart_capture(self.get_choose_nic(), self.filterBox.text())
        """
           点击开始后，过滤器不可编辑，开始按钮，网卡选择框全部设为不可选
           激活暂停、停止键、重新开始键
        """
        self.restart_action.setDisabled(False)
        self.start_action.setDisabled(True)
        self.filterBox.setEnabled(False)
        self.filterGoButton.setEnabled(False)
        self.choose_nicbox.setEnabled(False)
        self.pause_action.setEnabled(True)
        self.stop_action.setEnabled(True)
        self.timer.start(flush_time)

    def ipStatistics_clicked_action(self):
        """
        IP地址类型统计图绘制
        """
        IP = self.core.get_network_count()
        IPv4_count = IP["ipv4"]
        IPv6_count = IP["ipv6"]
        IP_count = IPv4_count + IPv6_count
        if IP_count == 0:
            reply = QMessageBox.information(
                self,
                "提示",
                "你还没有抓包！",
                QMessageBox.Cancel
                )
        else:
            IPv4_div = IPv4_count / IP_count
            IPv6_div = IPv6_count / IP_count
            data = {
                'IPv4': (IPv4_div, '#79d2a7'),
                'IPv6': (IPv6_div, '#dfa66c'),
            }

            fig = plt.figure(figsize=(6, 4))

            # 创建绘图区域
            xxx = fig.add_subplot(111)
            xxx.set_title('IPv4 & IPv6 Statistical Chart')

            # 生成x轴的每个元素的位置，列表是[1,2,3,4]
            xticks = arange(1, 3)

            # 自定义柱状图的每个柱的宽度
            bar_width = 0.6

            IP_type = data.keys()
            values = [x[0] for x in data.values()]
            colors = [x[1] for x in data.values()]

            # 画柱状图，设置柱的边缘为透明
            bars = xxx.bar(
                xticks,
                values,
                width=bar_width,
                edgecolor='none'
                )

            # 设置y轴的标签
            xxx.set_ylabel('Proportion')

            xxx.set_xticks(xticks)
            xxx.set_xticklabels(IP_type)

            # 设置x,y轴的范围
            xxx.set_xlim([0, 3.5])
            xxx.set_ylim([0, 1])

            # 给每一个bar分配颜色
            for bar, color in zip(bars, colors):
                bar.set_color(color)
            plt.show()

    def msgStatistics_clicked_action(self):
        """
        数据包类型数量统计
        """
        trans = self.core.get_transport_count()

        TCP_count = trans["tcp"]
        UDP_count = trans["udp"]
        ARP_count = trans["arp"]
        ICMP_count = trans["icmp"]

        if TCP_count + UDP_count + ARP_count + ICMP_count == 0:
            reply = QMessageBox.information(
                self,
                "提示",
                "你还没有抓包！",
                QMessageBox.Cancel
                )
        else:
            labels = ('TCP', 'ICMP', 'UDP', 'ARP')
            fracs = (TCP_count, ICMP_count, UDP_count, ARP_count)
            explode = [0.1, 0.1, 0.1, 0.1]  # 0.1 凸出这部分，
            plt.axes(aspect=1)  # set this , Figure is round, otherwise it is an ellipse
            # autopct ，show percet
            plt.pie(x=fracs,
                    labels=labels,
                    explode=explode,
                    autopct='%3.1f %%',
                    shadow=True,
                    labeldistance=1.1,
                    startangle=90,
                    pctdistance=0.6)
            plt.show()

    def openfile_button_clicked_action(self):
        """
        打开文件事件
        """
        if self.core.start_flag or self.core.pause_flag:
            QMessageBox.warning(
                self,
                "警告",
                "请停止当前抓包！"
                )
            return
        self.core.open_pcap_file()

    def savefile_button_clicked_action(self):
        """
        保存文件点击事件
        """
        if self.core.start_flag or self.core.pause_flag:
            QMessageBox.warning(
                self,
                "警告",
                "请停止当前抓包！"
                )
            return
        self.core.save_captured_to_pcap()

    def track_button_clicked_action(self):
        """
        菜单栏流量监测键点击事件
        """
        if not self.monitor or not self.monitor.is_alive():
            self.monitor = Process(
                target=start_monitor,
                daemon=True
                )
            self.monitor.start()

    def about_button_clicked_action(self):
        """
        关于软件点击事件
        """
        self.show_print("about")

    def readme_button_clicked_action(self):
        """
        使用文档点击事件
        """
        self.show_print("readme")

    def info_setupUi(self, subject):
        """
        使用文档和关于软件窗口
        """
        self.qwq.resize(750, 550)
        # 固定窗口大小
        self.qwq.setFixedSize(750, 550)
        ra_verticalLayout = QVBoxLayout(self.qwq)
        self.ra_tabWidget = QTabWidget(self.qwq)
        ra_about = QWidget()
        about_verticalLayout = QVBoxLayout(ra_about)
        self.ra_textBrowser = QTextBrowser(ra_about)
        # 关闭富文本模式
        self.ra_textBrowser.setAcceptRichText(False)
        # 设置字体大小
        self.ra_textBrowser.setFontPointSize(11)
        about_verticalLayout.addWidget(self.ra_textBrowser)
        self.ra_tabWidget.addTab(ra_about, "")
        # self.author = QWidget()
        # self.gridLayout = QGridLayout(self.author)
        # self.author_textBrowser = QTextBrowser(self.author)
        # self.gridLayout.addWidget(self.author_textBrowser, 0, 0, 1, 1)
        # self.ra_tabWidget.addTab(self.author, "")
        ra_verticalLayout.addWidget(self.ra_tabWidget)

        if subject == "readme":
            self.readme_show()
            self.readme_content()
        elif subject == "about":
            self.info_show()
            self.info_content()

    def info_show(self):
        self.qwq.setWindowTitle("关于软件")
        self.ra_tabWidget.setTabText(0, "WireKunpeng")
        self.ra_tabWidget.setTabToolTip(0, "功能介绍")
        # self.ra_tabWidget.setTabText(1, "作者")
        # self.ra_tabWidget.setTabToolTip(1, "作者信息")

    def info_content(self):
        """
        关于软件内容
        """
        self.ra_textBrowser.setText(
            "软件主要功能如下：\n\n"
            "1. 侦听指定网卡或所有网卡，抓取流经网卡的数据包；\n\n"
            "2. 解析捕获的数据包每层的每个字段，查看数据包的详细内容；\n\n"
            "3. 设置了BPF过滤器，可选择性捕获指定地址、端口或协议等相关条件的报文；\n\n"
            "4. 针对应用进行流量监测，并在流量图实时显示监测结果。可设置流量预警线，当流\n"
            "   量超过预警线时发出警告信息；\n\n"
            "5. 以饼状图的形式显示TCP、UDP、ARP及ICMP报文统计信息，以柱状图的形式表示\n"
            "   IPv4、IPv6报文统计信息；\n\n"
            "6. 可将捕获到的数据包另存为pcap文件\n\n"
            "7. 支持打开一个pcap文件并对其中的数据包进行解析；\n\n\n"
            "\t\t\t版本：WireKunpeng v1.0.1\n"
        )

    def readme_show(self):
        self.qwq.setWindowTitle("使用文档")
        self.ra_tabWidget.setTabText(0, "用户须知")
        self.ra_tabWidget.setTabToolTip(0, "注意事项")

    def readme_content(self):
        """
        使用说明内容
        """
        self.ra_textBrowser.setText(
            "\n！！本软件需要运行在已安装 Npcap 的计算机环境上！！\n"
            "\n！！本软件需要运行在已安装 Npcap 的计算机环境上！！\n"
            "\n！！本软件需要运行在已安装 Npcap 的计算机环境上！！\n\n"
            "！！请确保您的计算机已经安装 Npcap(https://nmap.org/npcap) 后"
            "运行本软件！！\n\n\n"
            "若需使用 filter 过滤器筛选符合指定条件的数据包，"
            "请在过滤框内输入符合 BPF 语法的过滤规则后重新开始抓包\n\n"
            "注意：\n"
            "filter 过滤器使用 BPF(Berkeley Packet Filter) 语法\n\n"
            "BPF 详见维基百科：https://en.wikipedia.org/wiki/Berkeley_Packet_Filter\n"
        )

    def show_print(self, sub):
        self.qwq = QWidget()
        self.info_setupUi(sub)
        self.qwq.show()

def start():
    app = QApplication()
    Ui_MainWindow().setupUi()
    app.exec_()
