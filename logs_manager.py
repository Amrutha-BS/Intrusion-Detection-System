#Log management
from os import listdir
from os.path import isfile, join
import os, time
from file_manager import files_desc
import datetime

def logs_management():
    #mypath="./"
    print()
    __author__='''
# =========================================================================|
#   Logs Manager has begun
# =========================================================================|

    '''
    print(__author__)
    prev_date=open("logs_manager_date","r")
    d=prev_date.read()
    print("The previous date of checking:"+str(d))
    prev_date.close()
    cur_date=datetime.datetime.now()
    today_date=open("logs_manager_date","w")
    today_date.write(str(cur_date))
    
    mypath=input("Enter the directory: ")
    f1 = open("logs_mypath", "r")
    prev_path=f1.read()
    
    #if mypath!=prev_path:
    files_desc(mypath)
    
    cur_files = {}
    new_files={}
    removed_files=[]
    modified_files={}
    '''
    for f in listdir(mypath):
        if os.path.isfile(f):
            stat = time.ctime(os.path.getmtime(f))
            cur_files[f]=stat
    '''
    for f0 in listdir(mypath):
            #print(mypath+'\\'+f)
            f=mypath+'\\'+f0
            if os.path.isfile(f):
                #print(f)
                stat = time.ctime(os.path.getmtime(f))
                cur_files[f]=stat    
    file="Files_LastModified"
    f = open(file, "r")
    content=eval(f.read())
    #print(content)
    #print(type(content))
    
    before_files=eval(content[mypath])
    #print("before")
    #print(before_files)
    #print(type(before_files))
    #print(type(cur_files))
    #print()
    #print("cur")
    #print(cur_files)
    #print()
    f.close()
    #print("*************")
    for i in cur_files:
        if i not in before_files:
            stat = time.ctime(os.path.getmtime(i))
            new_files[i]=stat
    #print(new_files)

    for i in before_files:
        if i not in cur_files:
            #stat = time.ctime(os.path.getmtime(i))
            removed_files.append(i)
    #print(removed_files)
            
    #print(removed_files)

    for i in cur_files:
        if i in before_files:
            stat = time.ctime(os.path.getmtime(i))
            #print(i)
            if before_files[i]!=stat:
                modified_files[i]=stat
    
    #Printing New Files 
    
    if len(new_files)!=0:
        print("############################ New Files ###########################################")
        print()
        print("File Name                                                   Time")
        for i in new_files:
            print(i+"                    "+new_files[i])
        print()
        print()
    else:
        print("No New Files detected\n")



    #Printing Modified Files 
    if len(modified_files)!=0:
        print("############################ Modified Files ###########################################")
        print()
        print("File Name                                                    Time")
        for i in modified_files:
            print(i+"                                "+modified_files[i])
 
        print()
        print()
    else:
        print("No Modified Files detected\n")


    #Printing Deleted Files
    if len(removed_files)!=0: 
        print("############################ Deleted Files ###########################################")
        print()
        print("File Name")
        for i in removed_files:
            print(i)
    else:
        print("No Deleted Files detected\n")
    print()
       
    #file="Files_LastModified"
    f = open(file, "w")
    #content=eval(f.read())
    content[mypath]=str(cur_files)
    f.write(str(content))
    f.close()
    print("Done....................")

if __name__=='__main__':
    print("Starting..")
    logs_management()

