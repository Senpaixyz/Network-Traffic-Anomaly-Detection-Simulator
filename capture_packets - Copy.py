from scapy.all import *
print(conf.iface)
"""Capture packets by Scapy
    pip3 install netifaces
    
    before run start: net start npcap # windows 
"""
import os
from datetime import datetime
from scapy.layers.inet import IP, TCP, UDP
from scapy.sendrecv import sniff
from scapy.utils import wrpcap

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
    for pkt in sniff(iface=conf.iface, count=10):
        pkt_buffer.append(pkt)
        pkt_time = pkt.time
        if len([fid for fid in flows.keys() if srcIP == fid[0]]) > 1000:  # number of flows
            wrpcap(out_file, pkt_buffer, append=True)  # appends packet to output file
            pkt_buffer = []
            break
        fid = _get_fid(pkt)

        if fid not in flow_buffer.keys():
            pre_pkt_time = pkt_time
            start_time = pkt_time
            flow_buffer[fid] = (1, start_time, pre_pkt_time)
        else:
            pre_pkt_time = flow_buffer[fid][2]
            if pkt_time - pre_pkt_time < TIMEOUT:  # 10mins = 10*60s
                flows[fid] = flow_buffer[fid]
                del flow_buffer[fid]  # pop out from the buffer
                flow_buffer[fid] = (1, pkt_time, pkt_time)
            else:
                flow_buffer[fid] = (flow_buffer[fid][0] + 1, start_time, pkt_time)

            # check flow_buffer and try to reduce its size
            for k in flow_buffer.keys():
                pkt_cnt, pkt_start_time, pre_pkt_time = flow_buffer[k]
                if pre_pkt_time - pkt_start_time > 60 * 60:  # 1 hour
                    flows[fid] = flow_buffer[fid]
                    del flow_buffer[fid]  # pop out from the buffer

        if len(pkt_buffer) > 10000:  # buffer size of packets
            wrpcap(out_file, pkt_buffer, append=True)  # appends packet to output file
            pkt_buffer = []

    wrpcap(out_file, pkt_buffer, append=True)  # appends packet to output file
    print(f'out_file: {os.path.abspath(out_file)}')

    end_capture_time = datetime.now()
    total_time = (end_capture_time - start_capture_time).total_seconds()
    print(f'capture finished at {end_capture_time}, and the total time is {total_time} s')


if __name__ == '__main__':
    get_device_interfaces(verbose=0)
    capture()