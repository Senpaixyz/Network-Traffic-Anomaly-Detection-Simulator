from scapy.all import *
print(conf.iface)
"""Capture packets by Scapy
    pip3 install netifaces
    
    before run start: net start npcap # windows 
"""
import os
import psutil
from datetime import datetime
from scapy.layers.inet import IP, TCP, UDP
from scapy.sendrecv import sniff
from scapy.utils import wrpcap
from library.FlowRecoder import get_data, gen_json
import pandas as pd
import csv
def _get_fid(pkt):
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


def get_device_interfaces(verbose=10):
    """Get the device interfaces (netcard)
    Parameters
    ----------
    verbose
    Returns
    -------
    """
    # not work on mac
    # from scapy.arch.windows import IFACES
    """Print list of available network interfaces"""
    # print(IFACES.show(resolve_mac))
    # print(IFACES.show())

    import netifaces
    from pprint import pprint

    ifaces = netifaces.interfaces()
    pprint(ifaces)
    if verbose >= 5:
        for intf in ifaces:
            print(f'\n***{intf}')
            pprint(netifaces.ifaddresses(intf))

    return ifaces


def set_filename_n(output_str):
    output_str = str(output_str)
    sanitize = output_str.replace(':', '-')
    sanitize = sanitize.replace('.', '-')
    sanitize_str = sanitize.replace(' ', '_')
    new_filename = sanitize_str
    return new_filename

def set_filename_n(output_str):
    output_str = str(output_str)
    sanitize = output_str.replace(':', '-')
    sanitize = sanitize.replace('.', '-')
    sanitize_str = sanitize.replace(' ', '_')
    new_filename = sanitize_str
    return new_filename
def capture():
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
    filename_tmp = 'packets/data-{0}.pcap'.format(start_capture_time)
    out_file = set_filename_n(filename_tmp)
    print(f'\ncapture starts at {start_capture_time}...')
    if os.path.exists(out_file):
        os.remove(out_file)

    pkt_buffer = []  # buffer size of packets
    flow_buffer = {}  # buffer size of flows
    srcIP = get_if_addr(conf.iface) # device local ip
    TIMEOUT = 10  # 600 seconds

    flows = {}
    DURATION = 12200
    seconds_pass = 0
    sleep_sec = 0.5
    check_packets_interval = 2
    c_stime = (0, 0)
    attrs = ['proto_name', 'sport', 'dport', 'proto', 'push_flag_ratio',
             'average_len', 'average_payload_len',
             'pkt_count', 'flow_average_inter_arrival_time', 'protocol', 'label']
    data = []
    captured_buffer = []
    while seconds_pass < DURATION:
        c_stime = ((seconds_pass // 60) + 10, seconds_pass % 60)
        print(str(c_stime[0]) + ":" + str(c_stime[1]))
        for pkt in sniff(iface=conf.iface, count=5):
            captured_buffer.append(pkt)
        seconds_pass += 1
        time.sleep(sleep_sec)
    print("Saving data...")
    data = get_data(captured_buffer)
    data = gen_json(data)


    df = pd.DataFrame(data)
    df['label'] = 'Normal'
    filename = "packets/Normal_packets-{0}D.csv".format(set_filename_n(start_capture_time))
    df.to_csv(filename, index=False, header=attrs)

if __name__ == '__main__':
    get_device_interfaces(verbose=0)
    capture()