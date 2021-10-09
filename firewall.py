#!/usr/bin/env python3
                                                      
from datetime import datetime
import socket,struct,os
#host = socket.gethostname()
#print(host)
#print(socket. gethostbyaddr("10.0.2.11"))
def BlockIT(ipaddr):
    os.popen("iptables -A INPUT -s {} -j DROP".format(ipaddr))
s = socket.socket(socket.PF_PACKET,socket.SOCK_RAW,8)
dict = {}
print("starting Firewall........")
while True:
    try:
        pkt = s.recvfrom(2048)
        ip_header = pkt[0][14:34]
        ip_hdr= struct.unpack("!8sB3s4s4s",ip_header)
        IP = socket.inet_ntoa(ip_hdr[3])

        tcp_header = pkt[0][34:54]
        tcp_hdr = struct.unpack("!HH9ss6s",tcp_header)

        if IP =="127.0.0.1" or IP == "10.0.2.11" :
            pass
        elif IP in dict.keys():
            if tcp_hdr[1] not in dict[IP]:
                dict[IP].append(tcp_hdr[1])
            if len(dict[IP]) ==5:
                print("This address was blocked".format(IP)) 
                print(dict)
                BlockIT(IP)
        else:
            dict[IP] = []
    except KeyboardInterrupt:
        print("Exited with CTRL+C")
        break                   
                  



'''
sudo iptables -t nat -F
sudo iptables -t mangle -F
sudo iptables -F
sudo iptables -X


host = socket.gethostbyname(socket.gethostname())
print(host)
'''                      
                                        
