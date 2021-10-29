from scapy.all import *
"""Capture packets by Scapy
    pip3 install netifaces
    
    before run start: net start npcap # windows 
"""
import os
from datetime import datetime
import time
from joblib import load
from scapy.layers.inet import IP, TCP, UDP
from scapy.sendrecv import sniff
from scapy.utils import wrpcap
from library.FlowRecoder import get_data, gen_json
import numpy as np
from sys import platform

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
        self.check_packets_interval = 5# every 5s the system check array of packets
        self.c_stime = (0, 0)
        self.knn_model = self.load_model()
        self.captured_buffer = []
        self.packets_percentage = []
        self.packets_percentage_bytes = []
        self.arrayBytesInstances = 0
        self.anomalyBytes = 0
    def load_model(self):
        model = None
        try:
            model = load('model/knn-data.joblib')
            return model
        except FileNotFoundError:
            print("Model File not Found!")
            sys.exit()

    def capture(self):
        """
                Parameters
                ----------
                get_data = convert pcap to much more readable
                get_json = get the readable packets then convert it to array  for predicction

        """

        while self.seconds_pass < self.DURATION:
            self.c_stime = ((self.seconds_pass//60)+10, self.seconds_pass%60)
            print(str(self.c_stime[0])+":"+str(self.c_stime[1]))
            message = ""
            self.captured_buffer = [] # Add mo to
            for pkt in sniff(iface=conf.iface, count=30): # set mo sa 20
                self.captured_buffer.append(pkt)
            data = get_data(self.captured_buffer)
            data = gen_json(data)
            self.predictByBytes(data)
            #print("JSON: ", data)
            if self.ctr == self.check_packets_interval:
                #print("DATA: ", data)
                print("CHECKING BYTES")
                perc = (self.anomalyBytes / self.arrayBytesInstances) * 100
                self.packets_percentage_bytes.append(perc)
                print("CHECKING PACKETS... ")
                self.prediction(data)
                self.ctr = 0
            self.ctr += 1
            self.seconds_pass += 1
            time.sleep(self.sleep_sec)
            #if platform == "win32":
            #    os.system('cls')
        return self.packets_percentage, self.packets_percentage_bytes

    def predictByBytes(self, packets_array):
        data = packets_array
        try:
            unique = np.unique(data,axis=0)
            print("DATA: ", data)
            print("UNIQUE: ", unique)
            if len(unique) <= 2 and len(data) > 2:
                self.anomalyBytes += 1
            self.arrayBytesInstances += 1
            print("LENGTH: ", len(unique), " TOTAL: ", self.arrayBytesInstances) # Hereeee
        except ValueError as e:
            print("Array values contains I dunno.... :) ")

    def prediction(self,packets_array):
        """ Anomaly from the previous packets flows """
        data = packets_array
        try:
            prediction_packets = self.knn_model.predict(data)
            print("PREDICTION: ", prediction_packets)
            alert = 0
            totalAlert = len(prediction_packets)
            prev = None
            nxt = None
            for i in range(0, len(prediction_packets)):
                if prediction_packets[i] == 0:
                    curr = prediction_packets[i]

                    if (i - 1) == -1:
                        prev = None
                    else:
                        prev = prediction_packets[i - 1]
                    if (i + 1) == len(prediction_packets):
                        nxt = None
                    else:
                        nxt = prediction_packets[i + 1]
                    if prev != None and nxt != None:
                        if prev == curr and nxt == curr:
                            alert += 1
                            #print("ALERT: ", alert)
                else:
                    alert = 0

            percentage_alert = (alert / totalAlert) * 100
            print("PERCENTAGE PACKETS: ", percentage_alert)
            self.packets_percentage.append(percentage_alert)
            print(self.packets_percentage)
        except ValueError:
            print("Input incorrect parameters...")






if __name__ == '__main__':
    app = AnomalyDetectionSimulator(duration=60) # duration in seconds
    packets_arrays,packets_bytes = app.capture()
    print("50-100% -> MEANS DDOS")
    print("0-50% -> MEANS NORMAL")
    print("-----------------1st way-------------------")
    print(packets_arrays)
    print("-----------------2nd way-------------------")
    print(packets_bytes)
