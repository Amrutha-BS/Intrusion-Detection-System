from queue import Queue
import time, socket, threading




def down_it(item):
	try:
		
		print('Checking', item, 'port')
		packet = str("GET / HTTP/1.1\nHost: " + host + "\n\n User-Agent: " + uagent + "\n" + headers).encode('utf-8')
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(2)
		s.connect((host, int(item)))
		if s.sendto(packet, (host, int(item))):
			datum.append(item)
		s.shutdown(1)
	except:
		time.sleep(.1)


def dos():
	while True:
		item = q.get()
		down_it(item)
		q.task_done()


def port_scan():
    global uagent
    global headers
    uagent = 'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3'
    headers = '''Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
    Accept-Language: en-us,en;q=0.5
    Accept-Encoding: gzip,deflate
    Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7
    Keep-Alive: 115
    Connection: keep-alive'''
    global q
    global datum
    global ports
    global threads
    global host
    q = Queue()
    datum = []
    ports = 1024

    threads = 150 # number of threads
    #host = '10.0.2.13' # host to be checked
    host=input("enter the IP Address:")
    for i in range(int(threads)):
        t = threading.Thread(target=dos)
        t.daemon = True
        t.start()
    item = 0
    while item < ports:
        if (item % 2000 == 0): # for no memory crash
            time.sleep(.1)
        item = item + 1
        q.put(item)
    q.join()


    print('\033[91m Host', host, 'Open ports:', ', '.join(str(x) for x in datum), '\033[0m')
    print(str(ports)+" ports scanned successfully....")
#port_scan()