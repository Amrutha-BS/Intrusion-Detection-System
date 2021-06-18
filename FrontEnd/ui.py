from tkinter import *
from tkinter import filedialog
import pandas as pd
from PIL import ImageTk,Image

def OpenFile():
	filepath =  filedialog.askopenfilename()
	df=pd.read_csv(filepath)
	print(df.head())
	#IDS function from here

def SnifferMode():
	global my_img1
	top=Toplevel()
	my_img1 = ImageTk.PhotoImage(Image.open("pes.png"))
	img1 = Label (top,image=my_img)
	img1.pack()
	top.title('Sniffer Mode')
	top.geometry("500x500+100+50")

	t1 = Label(top , text="")
	t1.pack()
	text = Label(top, text="Entering Sniffer Mode")
	text.pack()
	res = Label(top , text="Please Check command prompt for output")
	t2 = Label(top , text="")
	t2.pack()
	res.pack()
	#Sniffer Mode function from here

def LoggerMode():
	global my_img1
	top=Toplevel()
	my_img1 = ImageTk.PhotoImage(Image.open("pes.png"))
	img1 = Label (top,image=my_img)
	img1.pack()
	top.title('Logger Mode')
	top.geometry("500x500+100+50")

	t1 = Label(top , text="")
	t1.pack()
	text = Label(top, text="Entering Logger Mode")
	text.pack()
	res = Label(top , text="Please Check comand prompt for output")
	t2 = Label(top , text="")
	t2.pack()
	res.pack()
	#Logger Mode function from here


def NIDS():
	global my_img1
	top=Toplevel()
	my_img1 = ImageTk.PhotoImage(Image.open("pes.png"))
	img1 = Label (top,image=my_img)
	img1.pack()
	top.title('IDS')
	top.geometry("500x500+100+50")

	t = Label(top , text="Please open the file which contains the attacks")
	button = Button(top, text="Open file",command=OpenFile)
	t1 = Label(top , text="")
	t2 = Label(top , text="")
	t3 = Label(top , text="")
	res = Label(top , text="Please Check command prompt for output")
	t1.pack()
	t.pack()
	t2.pack()
	button.pack()
	t3.pack()
	res.pack()

def Honeypot():
	global my_img1
	top=Toplevel()
	my_img1 = ImageTk.PhotoImage(Image.open("pes.png"))
	img1 = Label (top,image=my_img)
	img1.pack()
	top.title('Honeypot')
	top.geometry("500x500+100+50")

	t1 = Label(top , text="")
	t1.pack()
	text = Label(top, text="Creating Honeypot")
	text.pack()
	res = Label(top , text="Please Check command prompt for output")
	t2 = Label(top , text="")
	t2.pack()
	res.pack()
	#Honepot function from here

def PortScan():
	global my_img1
	top=Toplevel()
	my_img1 = ImageTk.PhotoImage(Image.open("pes.png"))
	img1 = Label (top,image=my_img)
	img1.pack()
	top.title('Port Scan')
	top.geometry("500x500+100+50")

	t1 = Label(top , text="")
	t1.pack()
	text = Label(top, text="Perfoming Port Scan") 
	text.pack()
	res = Label(top , text="Please Check command prompt for output")
	t2 = Label(top , text="")
	t2.pack()
	res.pack()
	#PortScan fucntion from here

def FireWall():
	global my_img1
	top=Toplevel()
	my_img1 = ImageTk.PhotoImage(Image.open("pes.png"))
	img1 = Label (top,image=my_img)
	img1.pack()
	top.title('FireWall')
	top.geometry("500x500+100+50")

	t1 = Label(top , text="")
	t1.pack()
	text = Label(top, text="Enabling FireWall") 
	text.pack()
	res = Label(top , text="Please Check command prompt for output")
	t2 = Label(top , text="")
	t2.pack()
	res.pack()
	#Firewall fucniton from here


root = Tk()

mylabel=Label(root, text="")
mylabel1=Label(root, text="Anomaly Based Intrustion Detection System" , font=('Helvetica', 15, 'bold'))
mylabel2=Label(root, text="")
mylabel3=Label(root, text="")
mylabel4=Label(root, text="")
mylabel5=Label(root, text="")
mylabel6=Label(root, text="")
mylabel7=Label(root, text="")
mylabel8=Label(root, text="")


my_img = ImageTk.PhotoImage(Image.open("pes.png"))
img = Label (image=my_img)
img.pack()
mylabel.pack()
mylabel1.pack()
mylabel2.pack()

myButton1 = Button(root , text="Sniffer Mode" , padx=41 , command=SnifferMode , fg="blue")
myButton2 = Button(root , text="Logger Mode" , padx=41 , command=LoggerMode , fg="blue")
myButton3 = Button(root , text="NIDS" , padx=63 , command=NIDS , fg="blue")
myButton4 = Button(root , text="Honeypot" , padx=50 , command=Honeypot , fg="blue")
myButton5 = Button(root , text="Port Scan" , padx=52 , command=PortScan , fg="blue")
myButton6 = Button(root , text="Fire Wall" , padx=55 , command=FireWall , fg="blue")
myButton7 = Button(root , text="Exit" , padx=70 , command=root.quit , fg="blue")

myButton1.pack()
mylabel3.pack()
myButton2.pack()
mylabel4.pack()
myButton3.pack()
mylabel5.pack()
myButton4.pack()
mylabel6.pack()
myButton5.pack()
mylabel7.pack()
myButton6.pack()
mylabel8.pack()
myButton7.pack()


root.geometry("500x550+100+50")
root.title("Anomaly Based Intrustion Detection System")
root.mainloop()
