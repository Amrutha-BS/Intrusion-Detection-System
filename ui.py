from tkinter import *
from tkinter import messagebox
from tkinter import filedialog
from PIL import ImageTk,Image
from model import Intrusion_Detection
from Sniffer import packet_sniffer
from Logger import packet_logger
from PortScanner import port_scanner
from HoneyPot import honey_pot
from logs_manager import logs_management
from PS import port_scan

def delete():
	root.destroy()

def OpenFile():
	filepath =  filedialog.askopenfilename()
	#df=pd.read_csv(filepath)
	#print(df.head())
	#IDS function from here
    #df=pd.read_csv(filepath)
	Intrusion_Detection(filepath)

def SnifferMode():
	global my_img1
	top=Toplevel()
	my_img1 = ImageTk.PhotoImage(Image.open("pes.png"))
	img1 = Label (top,image=my_img)
	img1.pack()
	top.title('Sniffer Mode')
	top.iconbitmap('pes.ico')
	top.geometry("500x550+500+110")

	t1 = Label(top , text="")
	t1.pack()
	text = Label(top, text="Entering Sniffer Mode")
	text.pack()
	res = Label(top , text="Please Check command prompt for output")
	t2 = Label(top , text="")
	t2.pack()
	res.pack()
    #Sniffer Mode function from here
	done=packet_sniffer()
    #print("Sniffing done")

def LoggerMode():
	global my_img1
	top=Toplevel()
	my_img1 = ImageTk.PhotoImage(Image.open("pes.png"))
	img1 = Label (top,image=my_img)
	img1.pack()
	top.title('Logger Mode')
	top.iconbitmap('pes.ico')
	top.geometry("500x550+500+110")

	t1 = Label(top , text="")
	t1.pack()
	text = Label(top, text="Entering Logger Mode")
	text.pack()
	res = Label(top , text="Please Check comand prompt for output")
	t2 = Label(top , text="")
	t2.pack()
	res.pack()
	done=packet_logger()


def NIDS():
	global my_img1
	top=Toplevel()
	my_img1 = ImageTk.PhotoImage(Image.open("pes.png"))
	img1 = Label (top,image=my_img)
	img1.pack()
	top.title('IDS')
	top.iconbitmap('pes.ico')
	top.geometry("500x550+500+110")

	t = Label(top , text="Please open the file which contains the network traffic")
	button = Button(top, text="Open file",command=OpenFile, fg="white" , bg="#d77337")
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
	top.iconbitmap('pes.ico')
	top.geometry("500x550+500+110")

	t1 = Label(top , text="")
	t1.pack()
	text = Label(top, text="Creating Honeypot")
	text.pack()
	res = Label(top , text="Please Check command prompt for output")
	t2 = Label(top , text="")
	t2.pack()
	res.pack()
	done=honey_pot()

def PortScan():
	global my_img1
	top=Toplevel()
	my_img1 = ImageTk.PhotoImage(Image.open("pes.png"))
	img1 = Label (top,image=my_img)
	img1.pack()
	top.title('Port Scan')
	top.iconbitmap('pes.ico')
	top.geometry("500x550+500+110")

	t1 = Label(top , text="")
	t1.pack()
	text = Label(top, text="Perfoming Port Scan") 
	text.pack()
	res = Label(top , text="Please Check command prompt for output")
	t2 = Label(top , text="")
	t2.pack()
	res.pack()
	done=port_scan()

def LogsManagement():
	global my_img1
	top=Toplevel()
	my_img1 = ImageTk.PhotoImage(Image.open("pes.png"))
	img1 = Label (top,image=my_img)
	img1.pack()
	top.title('Logs Management')
	top.iconbitmap('pes.ico')
	top.geometry("500x550+500+110")

	t1 = Label(top , text="")
	t1.pack()
	text = Label(top, text="Logs Management being processed") 
	text.pack()
	res = Label(top , text="Please Check command prompt for output")
	t2 = Label(top , text="")
	t2.pack()
	res.pack()
    
	logs_management()


def FireWall():
	global my_img1
	top=Toplevel()
	my_img1 = ImageTk.PhotoImage(Image.open("pes.png"))
	img1 = Label (top,image=my_img)
	img1.pack()
	top.title('FireWall')
	top.iconbitmap('pes.ico')
	top.geometry("500x550+500+110")

	t1 = Label(top , text="")
	t1.pack()
	text = Label(top, text="Enabling FireWall") 
	text.pack()
	res = Label(top , text="Please Check command prompt for output")
	t2 = Label(top , text="")
	t2.pack()
	res.pack()
	#Firewall fucniton from here

def Home():
	top=Toplevel()
	mylabel=Label(top, text="")
	mylabel1=Label(top, text="Anomaly Based Intrustion Detection System" , font=('Helvetica', 15, 'bold'))
	mylabel2=Label(top, text="")
	mylabel3=Label(top, text="")
	mylabel4=Label(top, text="")
	mylabel5=Label(top, text="")
	mylabel6=Label(top, text="")
	mylabel7=Label(top, text="")
	mylabel8=Label(top, text="")
	mylabel9=Label(top, text="")
	mylabel10=Label(top, text="")

	global my_img
	my_img = ImageTk.PhotoImage(Image.open("pes.png"))
	img = Label (top,image=my_img)
	img.pack()
	mylabel.pack()
	mylabel1.pack()
	mylabel2.pack()
	mylabel10.pack()

	Frame1 = Frame(top , bg='#80c1ff')
	Frame1.place(x=150 , y=220 , height=490 , width=250)

	myButton1 = Button(top , text="Sniffer Mode" , fg="white" , bg="#d77337" , font=("times new roman",15) , padx=41 , command=SnifferMode)
	myButton2 = Button(top , text="Logger Mode" ,  fg="white" , bg="#d77337" , font=("times new roman",15) , padx=41 , command=LoggerMode)
	myButton3 = Button(top , text="NIDS" ,  fg="white" , bg="#d77337", font=("times new roman",15) , padx=73 , command=NIDS)
	myButton4 = Button(top , text="Honeypot" ,  fg="white" , bg="#d77337", font=("times new roman",15) , padx=57 , command=Honeypot)
	myButton5 = Button(top , text="Port Scan" ,  fg="white" , bg="#d77337", font=("times new roman",15) , padx=57 , command=PortScan)
	myButton6 = Button(top , text="Logs Management" ,  fg="white" , bg="#d77337", font=("times new roman",15) ,padx=25 , command=LogsManagement)
	myButton7 = Button(top , text="Fire Wall" ,  fg="white" , bg="#d77337", font=("times new roman",15) , padx=57 , command=FireWall)
	myButton8 = Button(top , text="Exit" ,  fg="white" , bg="#d77337", font=("times new roman",15) , padx=77 , command=root.quit )


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
	mylabel9.pack()
	myButton8.pack()
	top.resizable(False,False)
	top.geometry("550x750+500+70")
	top.iconbitmap('pes.ico')
	top.title("Anomaly Based Intrustion Detection System")


def login_function():
	if txt_pass.get()=="" or txt_user.get()=="":
		messagebox.showerror("Error","All fields are required",parent=root)

	elif txt_pass.get()!="12345" or txt_user.get()!="Admin":
		messagebox.showerror("Error","Invalid Username/password",parent=root)
	else:
		messagebox.showinfo("Logged In","Successfully Logged in",parent=root)
		text = Label(root,text="Logged In" , fg="green")
		text.place(x=470,y=560)
		text1 = Label(root,text="(Please dont close this tab)" , fg="red")
		text1.place(x=430,y=580)
		Home()

global root
root=Tk()
root.geometry("600x600+450+100")
root.resizable(False,False)
root.iconbitmap('pes.ico')
root.title("Admin Login")

bg=ImageTk.PhotoImage(file="pes.jpg")
bg_image=Label(root , image=bg).place(x=0 , y=75 , relwidth=1 , relheight=1)

Frame_login = Frame(root , bg="white")
Frame_login.place(x=50 , y=20 , height=220 , width=500)

title = Label(Frame_login , text="Admin Login" , font=("Impact",20,"bold") , fg="#d77337" , bg="white").place(x=90,y=15)
#desc = Label(Frame_login , text="Admin Login" , font=("Goudy old style",15,"bold") , fg="#d25d17" , bg="white").place(x=90,y=50)
		
uname = Label(Frame_login , text="User name" , font=("Goudy old style",15,"bold") , fg="gray" , bg="white").place(x=90,y=50)
txt_user=Entry(Frame_login,font=("times new roman",15),bg="lightgray")
txt_user.place(x=90 , y=80 , width =350 ,height=35)

passw = Label(Frame_login , text="Password" , font=("Goudy old style",15,"bold") , fg="gray" , bg="white").place(x=90,y=140)
txt_pass=Entry(Frame_login,font=("times new roman",15),bg="lightgray")
txt_pass.place(x=90 , y=170 , width =350 ,height=35)
txt_pass.config(show='*')

Login_btn = Button(root , command=login_function , text="Login" , fg="white" , bg="#d77337" , font=("times new roman",20)).place(x=250,y=500)

root.mainloop()
