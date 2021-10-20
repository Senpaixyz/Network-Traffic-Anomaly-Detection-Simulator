from scapy.all import *
"""Capture packets by Scapy
    pip3 install netifaces
    
    before run start: net start npcap # windows 
"""
import os
from datetime import datetime
import time
from scapy.layers.inet import IP, TCP, UDP
from scapy.sendrecv import sniff
from scapy.utils import wrpcap
from library.FlowRecoder import get_data, gen_json


class AnomalyDetectionSimulator(object):

    def __init__(self, duration=30):
        self.pkt_buffer = []  # buffer size of packets
        self.flow_buffer = {}  # buffer size of flows
        self.srcIP = get_if_addr(conf.iface) # device local ip
        self.TIMEOUT = 10  # 600 seconds
        self.flows = {}
        self.interface = conf.iface
        self.pkt_time = None
        self.ctr = 0
        self.DURATION = duration
        self.seconds_pass = 0
        self.sleep_sec = 0.5
        self.check_packets_interval = 2
        self.c_stime = (0, 0)
    def _get_fid(self, pkt):
        """Extract fid (five-tuple) from a packet: only focus on IPv4
        Parameters
        ----------
        Returns
        -------
            fid: five-tuple
        """

        if IP in pkt and TCP in pkt:
            flow_type = 'TCP'
            fid = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport, 6)
        elif IP in pkt and UDP in pkt:
            flow_type = 'UDP'
            fid = (pkt[IP].src, pkt[IP].dst, pkt[UDP].sport, pkt[UDP].dport, 17)
        else:
            fid = ('', '', -1, -1, -1)

        return fid

    def set_filename_n(self, output_str):
        sanitize = output_str.replace(':', '-')
        sanitize = sanitize.replace('.', '-')
        sanitize_str = sanitize.replace(' ', '_')
        new_filename = sanitize_str
        return new_filename

    def gather_datasets(self,filename="normal"):
        """
        Parameters
        ----------
        iface: str
            netcard interface
        out_file: file name
            store all captured packets to out_file
        Returns
        -------
        out_file:
        """
        start_capture_time = datetime.now()
        filename_tmp = 'packets/{0}-{1}.pcap'.format(filename, start_capture_time)
        out_file = self.set_filename_n(filename_tmp)
        print(f'\ncapture starts at {start_capture_time}...')
        if os.path.exists(out_file):
            os.remove(out_file)

        for pkt in sniff(iface=self.interface, count=200):
            self.pkt_buffer.append(pkt)
            self.pkt_time = pkt.time
            if len([fid for fid in self.flows.keys() if self.srcIP == fid[0]]) > 1000:  # number of flows
                wrpcap(out_file, self.pkt_buffer, append=True)  # appends packet to output file
                pkt_buffer = []
                break
            fid = self._get_fid(pkt)

            if fid not in self.flow_buffer.keys():
                pre_pkt_time = self.pkt_time
                start_time = self.pkt_time
                self.flow_buffer[fid] = (1, start_time, pre_pkt_time)
            else:
                pre_pkt_time = self.flow_buffer[fid][2]
                if self.pkt_time - pre_pkt_time < self.TIMEOUT:  # 10mins = 10*60s
                    self.flows[fid] = self.flow_buffer[fid]
                    del self.flow_buffer[fid]  # pop out from the buffer
                    self.flow_buffer[fid] = (1, self.pkt_time, self.pkt_time)
                else:
                    self.flow_buffer[fid] = (self.flow_buffer[fid][0] + 1, start_time, self.pkt_time)

                # check flow_buffer and try to reduce its size
                for k in self.flow_buffer.keys():
                    pkt_cnt, pkt_start_time, pre_pkt_time = self.flow_buffer[k]
                    if pre_pkt_time - pkt_start_time > 60 * 60:  # 1 hour
                        self.flows[fid] = self.flow_buffer[fid]
                        del self.flow_buffer[fid]  # pop out from the buffer

            if len(self.pkt_buffer) > 10000:  # buffer size of packets
                wrpcap(out_file, self.pkt_buffer, append=True)  # appends packet to output file
                self.pkt_buffer = []
        wrpcap(out_file, self.pkt_buffer, append=True)  # appends packet to output file
        print(f'out_file: {os.path.abspath(out_file)}')

        end_capture_time = datetime.now()
        total_time = (end_capture_time - start_capture_time).total_seconds()
        print(f'capture finished at {end_capture_time}, and the total time is {total_time} s')


    def capture(self):
        """
                Parameters
                ----------
                Te

        """
        start_capture_time = datetime.now()
        captured_buffer = []

        # for pkt in sniff(iface=conf.iface, count=50):
        #     captured_buffer.append(pkt)
        # data = get_data(captured_buffer)
        # data = gen_json(data)
        # print(data)
        while self.seconds_pass < self.DURATION:
            self.c_stime = ((self.seconds_pass//60)+10, self.seconds_pass%60)
            print(str(self.c_stime[0])+":"+str(self.c_stime[1]))
            if self.ctr == self.check_packets_interval:
                #stime_raw = (c_stime[0]*60)+c_stime[1]
                print("Check packets called")
                for pkt in sniff(iface=conf.iface, count=5):
                    captured_buffer.append(pkt)
                data = get_data(captured_buffer)
                data = gen_json(data)
                print(data)
                self.ctr = 0
            self.ctr += 1
            self.seconds_pass += 1
            time.sleep(self.sleep_sec)


if __name__ == '__main__':
    app = AnomalyDetectionSimulator(duration=30)
    #app.gether_datasets(filename="normal")
    app.capture()