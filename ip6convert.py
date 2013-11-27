#! /usr/bin/env python

"""
Copyright (c) 2013, Joel Parker
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the owner nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

__author__ = 'Joel Parker'
__copyright__ = 'Copyright 2013'
__license__ = 'BSD 3-Clause License'

from scapy.all import IP,Ether,IPv6,rdpcap,wrpcap,ls
import os
import argparse

#Taken from if_ether.h 
ETH_P_IP=0x0800
ETH_P_IPV6=0x86DD

DEFAULT_PCAP_INPUT_FILE = './pkts.pcap'

def ip4Toip6(ip4_str):
    """Given a IPv4 string address, return the IPv4-mapped IPv6 Address."""
    return '::FFFF:' + ip4_str

def ip6_pcap_file_name(file_path_string):
    """Add _IPv6 suffix before a file's extension."""
    fileName, fileExtension = os.path.splitext(file_path_string)
    return fileName + '_IPv6' + fileExtension

def parse_cli_options():
    """Parse command line options used in main()."""
    parser = argparse.ArgumentParser(description='Convert Packets in a pcap file to IPv6 using scapy')
    parser.add_argument('--file','-f', type=str, help='Path of pcap file to convert', default=DEFAULT_PCAP_INPUT_FILE)
    parser.add_argument('--output','-o', type=str, help='Path to write converted Pcap file')
    return parser

def write_ipv6_pcap_file(input_file_path,output_file_path):
    """Write a pcap file of traffic converted to IPv6.

       Limitations:
        - Currently non Ethernet frames are skipped.
        - Layers may go missing if you encapsulate IPv4 in IPv6

    """
    ipv6_pkts = []

    pkts = rdpcap(input_file_path)

    for pkt in pkts:    
        #Ignore Non Ethernet for the moment
        if type(pkt) != Ether:
            print("Skipping non Ethernet packet")
            continue
    
        #If IPv6 just add packet to to list
        if pkt.type == ETH_P_IPV6:
            print "Packet is alread IPv6"
            ipv6_pkts.append(pkt)
            continue
    
        iplayer = pkt.getlayer(IP)
        if iplayer != None:
            ip6layer = IPv6()
            ip6layer.dst = ip4Toip6(iplayer.dst)
            ip6layer.src = ip4Toip6(iplayer.src)
            ip6layer.payload = iplayer.payload
            pkt.type = ETH_P_IPV6
            pkt.payload = ip6layer
            #Recalulate the checksums of layers
            # and add missing fields http://stackoverflow.com/a/11648093/620304
            del ip6layer.payload.chksum
            ipv6_pkts.append(pkt)
        else:
            print("Skipping packet\n" +  ls(pkt))
        
    #Write the new pcap
    wrpcap(output_file_path,ipv6_pkts)
    print("Packets written to " + output_file_path)

def main():

    parser = parse_cli_options()	
    args = parser.parse_args()	
    
    original_pcap_file = args.file
    if args.output:
        ip6_pcap_file = args.output
    else:
        ip6_pcap_file = ip6_pcap_file_name(original_pcap_file)
    
    write_ipv6_pcap_file(original_pcap_file,ip6_pcap_file)

if __name__ == '__main__':
    main()
