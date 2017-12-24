from PyQt4 import QtGui  
from PyQt4.QtCore import *
import textwrap
import sys    
import socket
import time
import os  
from network.ethernet import Ethernet
from network.ipv4 import IPv4
from network.icmp import ICMP
from network.tcp import TCP
from network.udp import UDP
from network.pcap import Pcap
from network.http import HTTP

TAB_1 = '\t -'
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '

qtCreatorFile = "networks.ui"

Ui_MainWindow, QtBaseClass = uic.loadUiType(qtCreatorFile)

class networks(QtGui.QMainWindow, Ui_MainWindow):
    def __init__(self):
        #######
		QtGui.QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.setupUi(self)
		#######
        self.start_btn.clicked.connect(self.start_sniff)
        self.stop_btn.clicked.connect(self.stop_sniff)
		textEdit_Packet.setReadOnly(True)
		self.radioButton_data.setChecked(True)
        self.b1.toggled.connect(lambda:self.btnstate(self.radioButton_data))
		self.radioButton_details.setChecked(False)
        self.b1.toggled.connect(lambda:self.btnstate(self.radioButton_details))
        self.mythread = YourThreadName()
        self.connect(self.mythread,SIGNAL("start(QString)"),self.threadStart,Qt.DirectConnection)


    def btnstate(self,b,s):
      if b.text() == "Packet data":
         if b.isChecked() == True:
            showData(self)
         else:
            showDetails(self)
				
      if b.text() == "Packet Details":
         if b.isChecked() == True:
            showDetails(self)
         else:
            showData(self)
			
			
	def threadStart(self,id):
        time.sleep(0.05	)
        self.listWidget.addItem(id)
        self.listWidget
        
    def start_sniff(self):
        print("start sniff")
        self.listWidget.clear()
        self.mythread.start()

    def stop_sniff(self):
        print("stop sniff")
        self.mythread.terminate()
		
		
	
				
    def showDetails(self):
        print("show Details")
        self.listWidget_2.clear()
        id_chosen=self.textEdit_ID.text()
        self.listWidget_2.addItem(sniff[int(id_chosen)][1])
        self.listWidget_2

    def showData(self):
        print("show Data")
        self.listWidget_2.clear()
        id_chosen=self.textEdit_ID.text()
        self.listWidget_2.addItem(str(sniff[int(id_chosen)][2]))
        self.listWidget_2


class YourThreadName(QThread):

	def __init__(self,parent=None):
		super(YourThreadName,self).__init__(parent)
		
		
	def get_mac_addr(mac_raw):
		byte_str = map('{:02x}'.format, mac_raw)
		mac_addr = ':'.join(byte_str).upper()
		return mac_addr	
	
	
	def format_multi_line(prefix, string, size=80):
		size -= len(prefix)
		if isinstance(string, bytes):
			string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
			if size % 2:
				size -= 1
		return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])
	
	
	def __del__(self):
		self.wait()
		
		
	def run(self):
		conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
		x = 0
		while True:
			raw_data, addr = conn.recvfrom(65535)
			eth = Ethernet(raw_data)
			ipv4 = IPv4(eth.data)
			y = ''
			tcp = TCP(ipv4.data)
			if eth.proto== 8:
				if ipv4.proto == 1:
					y = "ICMP"
				elif ipv4.proto == 6:
						if (len(tcp.data) > 0) and (tcp.src_port == 80 or tcp.dest_port == 80):
							y = "HTTP"
						else:
							y = "TCP"
				elif ipv4.proto == 17:
					y = "UDP"
				else:
					y = "OTHER"

				sniff.append(['ID: '+str(x)+ ' Source: {}, Target: {}, Protocol: {} '.format(ipv4.target, ipv4.src,y)])
				self.emit(SIGNAL("start(QString)"),sniff[x][0])
				sniff[x].append(TAB_1 + 'IPv4 Packet: \n'+TAB_2 + 'Version: {}, Header Length: {}, TTL: {},\n'.format(ipv4.version, ipv4.header_length, ipv4.ttl)+TAB_2 + ' Destination: {}, Source: {}, Protocol: {}\n'.format(eth.dest_mac, eth.src_mac, eth.proto))

            # ICMP
				if ipv4.proto == 1:
					icmp = ICMP(ipv4.data)
					sniff[x][1]+=(TAB_1 + 'ICMP Packet:\n'+TAB_2 + 'Type: {}, Code: {}, Checksum: {},\n'.format(icmp.type, icmp.code, icmp.checksum)+TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4.proto, ipv4.src, ipv4.target))
					sniff[x].append(TAB_2 + 'ICMP Data:\n'+format_multi_line(DATA_TAB_3, icmp.data))

            # TCP
				elif ipv4.proto == 6:
					tcp = TCP(ipv4.data)
					sniff[x][1]+=(TAB_1 + 'TCP Segment:'+TAB_2 + 'Source Port: {}, Destination Port: {}\n'.format(tcp.src_port, tcp.dest_port)+TAB_2 + 'Sequence: {}, Acknowledgment: {}\n'.format(tcp.sequence, tcp.acknowledgment)+TAB_2 + 'Flags:\n'+TAB_3 + 'URG: {}, ACK: {}, PSH: {}\n'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh)+TAB_3 + 'RST: {}, SYN: {}, FIN:{}\n'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin))

					if len(tcp.data) > 0:

				        # HTTP
						if tcp.src_port == 80 or tcp.dest_port == 80:
							sniff[x].append(TAB_2 + 'HTTP Data:')
							try:
								http = HTTP(tcp.data)
								http_info = str(http.data).split('\n')
								for line in http_info:
									sniff[x][2]+=(DATA_TAB_3 + str(line))
							except:
								sniff[x][2]+=(format_multi_line(DATA_TAB_3, tcp.data))
						else:
							sniff[x].append(TAB_2 + 'TCP Data:')
							sniff[x][2]+=(format_multi_line(DATA_TAB_3, tcp.data))
					else:
						sniff[x].append(' ')

				# UDP
				elif ipv4.proto == 17:
					udp = UDP(ipv4.data)
					sniff[x][1]+=(TAB_1 + 'UDP Segment:\n'+TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp.src_port, udp.dest_port, udp.size))
					sniff[x].append(udp.data)
				# Other IPv4
				else:
					sniff[x].append(TAB_1 + 'Other IPv4 Data:\n'+format_multi_line(DATA_TAB_2, ipv4.data))
				

				x=x+1
	       

def main():
    app = QtGui.QApplication(sys.argv)
    form = networks()
    form.show()
    app.exec_()

if __name__ == '__main__':  # if we're running file directly and not importing it
	sniff = []

	main()  # run the main function