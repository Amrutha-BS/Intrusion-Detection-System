import os
import sys                                        
import platform                                   
import time
import socket
import argparse   
import subprocess

#from netfilter.rule import Rule,Match,Target
#import netfilter.table                                
                                              
                                              
def honey_pot():
    host = socket.gethostbyname(socket.gethostname())
    print('IP: {}'.format(host))
    '''
    if os.name == "nt":
        #host = socket.gethostbyname(socket.gethostname())
        #print('IP: {}'.format(host))
        s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP)
       
        s.bind((host,0))
        s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
        s.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)
    else:
        s=socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))   
    '''        
    try:
        #host = socket.gethostbyname(socket.gethostname())
        #print('IP: {}'.format(host))
        port=int(input("Enter the port number:"))
        print("Starting honeypot ...")                   
        time.sleep(5)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
              
        s.bind((host,port))
        while True:
            s.listen(5)
            conn,addr = s.accept()                            
            print("Honeypot has been visited by:")
            print("IP Address: ",addr[0],"Port no: ", addr[1])
       
   
    except KeyboardInterrupt:
        print("\nShutdown honeypot ...")
        s.con.close()
        return 0
#honey_pot()
