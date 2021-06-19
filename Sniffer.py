
# import modules
import socket 
import struct
import binascii
import os
import pye

# print author details on terminal
def packet_sniffer():
    print(pye.__author__)

    # if operating system is windows
    if os.name == "nt":
        host = socket.gethostbyname(socket.gethostname())
        print('IP: {}'.format(host))
        s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP)
        #print(s)
        s.bind((host,0))
        s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
        s.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)

    # if operating system is linux
    else:
        s=socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))

    # create loop 
    try:
        while True:

            # Capture packets from network
            pkt=s.recvfrom(65536)
            print(pkt)
            # extract packets with the help of pye.unpack class 
            unpack=pye.unpack()

            print("\n\n[+] ------------ Ethernet Header----- [+]")

            # print data on terminal
            for i in unpack.eth_header(pkt[0][0:14]).items():
                a,b=i
                print("{} : {} | ".format(a,b),)
            print("\n[+] ------------ IP Header ------------[+]")
            for i in unpack.ip_header(pkt[0][14:34]).items():
                a,b=i
                print("{} : {} | ".format(a,b),)
            print("\n[+] ------------ Tcp Header ----------- [+]")
            for  i in unpack.tcp_header(pkt[0][34:54]).items():
                a,b=i
                print("{} : {} | ".format(a,b),)

    except KeyboardInterrupt:
        #print '%s' % sys.exc_type
        print()
        print()
        print("shutting down.....")
        print()
        print("Sniffer shut down")
        #print ('%d packets received, %d packets dropped' %d packets dropped by interface') % p.stats()
        return 0
#packet_sniffer()