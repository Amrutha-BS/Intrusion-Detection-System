#Logger.py
# import modules
import socket 
import struct
import binascii
import os
import pye
import datetime
# print author details on terminal
def packet_logger():
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
    
        ct = datetime.datetime.now()
        ts = ct.timestamp()
        file='File'+str(ts)
        f = open(file, "a")
        l=[]
        while True:

            # Capture packets from network
            
            pkt=s.recvfrom(65536)
            
            #f.write("Woops! I have deleted the content!")
            
            f.write(str(pkt))
            print(pkt)
            print()
            # extract packets with the help of pye.unpack class 
            unpack=pye.unpack()
            #print("\n\n[+] ------------ Ethernet Header----- [+]")
            f.write("\n\n[+] ------------ Ethernet Header----- [+]")

            # print data on terminal
            for i in unpack.eth_header(pkt[0][0:14]).items():
                a,b=i
                f.write("{} : {} | ".format(a,b),)
            f.write("\n[+] ------------ IP Header ------------[+]")
            for i in unpack.ip_header(pkt[0][14:34]).items():
                a,b=i
                f.write("{} : {} | ".format(a,b),)
            f.write("\n[+] ------------ Tcp Header ----------- [+]")
            for  i in unpack.tcp_header(pkt[0][34:54]).items():
                a,b=i
                f.write("{} : {} | ".format(a,b),)

    except KeyboardInterrupt:
        #print '%s' % sys.exc_type
        print()
        print()
        print("shutting down.....")
        #print("l:",l)
        #f.writelines(l)
        f.close()
        print("packets have been logged in",file)
        #print ('%d packets received, %d packets dropped' %d packets dropped by interface') % p.stats()
        return 0
#x=packet_logger()
#exit()
