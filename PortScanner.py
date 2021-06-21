#!/usr/bin/python3

import socket




def port_scanner():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)

    host = input("Please enter the IP you want to scan: ")
    port = int(input("Please enter the port you want to scan: "))
    if s.connect_ex((host, port)):
        print("The port is closed")
    else:
        print("The port is open")
    print("port scanning closing............")
    return 0
#port_scanner(port)