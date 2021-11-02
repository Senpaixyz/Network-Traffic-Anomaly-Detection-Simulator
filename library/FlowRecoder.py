import sys
import hashlib
import json
from hashlib import md5
from scapy.all import *
from library.tcp_stream import TCPStream
from library.udp_stream import UDPStream
import argparse
from library.entropy import kolmogorov, shannon
import warnings
import numpy as np
attrs = ['src','sport','dst',
         'dport','proto','push_flag_ratio',
         'average_len','average_payload_len',
         'pkt_count','flow_average_inter_arrival_time']

def proto_name(sport,dport,use_dpi=False,payload=None):
    if dport == 80 or sport == 80 or dport == 8080 or sport == 8080:
        return "http"
    if dport == "https" or sport == "https":
        return "https"
    if dport == 443 or sport == 443:
        return "stream"
    if dport == 53 or sport == 53:
        return "dns"
    if dport == 3306 or sport == 3306:
        return "mysql"
    if dport == 22 or sport == 22:
        return "ssh"
    return "None"

def create_forward_flow_key(pkt):
    return "%s:%s->%s:%s:%s"%(pkt.src,pkt.sport,pkt.dst,pkt.dport,pkt.proto)

def create_reverse_flow_key(pkt):
    return "%s:%s->%s:%s:%s"%(pkt.dst,pkt.dport,pkt.src,pkt.sport,pkt.proto)

def create_flow_keys(pkt):
    return create_forward_flow_key(pkt),create_reverse_flow_key(pkt)

def get_flows(flows, protocol):
    packets_data = []
    for flow in flows.values():
        each_packet = []
        each_packet.append(round(flow.avrg_len(), 2))
        each_packet.append(round(flow.avrg_payload_len(), 2))
        """
        if proto_name(flow.sport, flow.dport) == "dns":
            each_packet.append(0)
        elif proto_name(flow.sport, flow.dport) == "http":
            each_packet.append(1)
        elif proto_name(flow.sport, flow.dport) == "https":
            each_packet.append(2)
        elif proto_name(flow.sport, flow.dport) == "None":
            each_packet.append(3)
        elif proto_name(flow.sport, flow.dport) == "mysql":
            each_packet.append(4)
        elif proto_name(flow.sport, flow.dport) == "ssh":
            each_packet.append(5)
        elif proto_name(flow.sport, flow.dport) == "stream":
            each_packet.append(6)
        each_packet.append(flow.sport)
        each_packet.append(flow.dport)

        each_packet.append(round(flow.push_flag_ratio(),2))
        each_packet.append(round(flow.avrg_len(),2))
        each_packet.append(round(flow.avrg_payload_len(),2))
        each_packet.append(flow.pkt_count)
        each_packet.append(flow.avrg_inter_arrival_time())
        if protocol == 'tcp':
            each_packet.append(0)
        elif protocol == 'udp':
            each_packet.append(1)
        packets_data.append(each_packet)"""
        each_packet.append(flow.proto)
        packets_data.append(each_packet)
    return packets_data
def gen_json(flows):
    data = []
    flows = flows
    #print(flows)
    if len(flows[0]) > 0:
        tcp_flows = get_flows(flows[0], 'tcp')
        for a in tcp_flows:
            data.append(a)
    if len(flows[1]) > 0:
        udp_flows = get_flows(flows[1], 'udp')
        for a in udp_flows:
            data.append(a)
    return data
    #result = dict()
    #index = 1
    # for flow in flows.values():
    #     data = dict()
    #     data['proto_name']              = proto_name(flow.sport,flow.dport)
    #     data['src']                     = flow.src
    #     data['sport']                   = flow.sport
    #     data['dst']                     = flow.dst
    #     data['dport']                   = flow.dport
    #     data['proto']                   = flow.proto
    #     data['push_flag_ratio']         = round(flow.push_flag_ratio(),2)
    #     data['avrg_len']                = round(flow.avrg_len(),2)
    #     data['avrg_payload_len']        = round(flow.avrg_payload_len(),2)
    #     data['pkt_count']               = flow.pkt_count
    #     data['avrg_inter_arrival_time'] = flow.avrg_inter_arrival_time()
    #
    #     result[index] = data
    #     index += 1
    # return json.dumps(result, indent=4, sort_keys=False)
    
def get_data(path):
    packets = path#rdpcap(path)
    packets_udp = path
    protocol = []
    flows = dict()
    flows_udp = dict()
    packets = [ pkt for pkt in packets if IP in pkt for p in pkt if TCP in p ]
    udp_packets = [ pkt for pkt in packets_udp if IP in pkt for p in pkt if UDP in p ]
    if len(packets)>0:
        for pkt in packets:
            flow_tuple = reverse_flow_tuple = key_to_search = None
            flow_tuple,reverse_flow_tuple = create_flow_keys(pkt[IP])

            if flow_tuple in flows.keys():
                flow_key,tcp_stream = flow_tuple, flows[flow_tuple]
            elif reverse_flow_tuple in flows.keys():
                flow_key,tcp_stream = reverse_flow_tuple, flows[reverse_flow_tuple]
            else:
                flow_key,tcp_stream = flow_tuple, None

            if tcp_stream is None:
                tcp_stream = TCPStream(pkt[IP])
            else:
                tcp_stream.add(pkt[IP])
            flows[flow_key] = tcp_stream
        protocol.append(flows)
    else:
        protocol.append([])
    if len(packets_udp)>0:
        for pkt in udp_packets:
            udp_stream = flow_key = flow_tuple = reverse_flow_tuple = key_to_search = None
            flow_tuple,reverse_flow_tuple = create_flow_keys(pkt[IP])

            if flow_tuple in flows_udp.keys():
                flow_key,udp_stream = flow_tuple, flows_udp[flow_tuple]
            elif reverse_flow_tuple in flows_udp.keys():
                flow_key,udp_stream= reverse_flow_tuple, flows_udp[reverse_flow_tuple]
            else:
                flow_key,udp_stream = flow_tuple, None

            if udp_stream is None:
                udp_stream = UDPStream(pkt[IP])
            else:
                udp_stream.add(pkt[IP])
            flows_udp[flow_key] = udp_stream
        protocol.append(flows_udp)
    else:
        protocol.append([])
    return protocol


