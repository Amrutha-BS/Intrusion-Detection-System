import os, os.path
import time
import glob

#FOLDER_PATH = r'C:/Users/DELL/OneDrive/Desktop/frontend'

def listDir(dir):
	rootdir=dir
	print('	File name 				File path')
	for root, dirname, files in os.walk(rootdir):
		for x in files:
			print(x +'			'+root + '\\' + x)
			#print(root + '\\' + x)
			print('\n')

	'''fileNames = os.listdir(dir)
	for fileName in fileNames:
		modTimesinceEpoc = os.path.getmtime(fileName)
		modificationTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(modTimesinceEpoc))
		 
		print('File Name: ' + fileName)
		print('Folder Path: ' + os.path.abspath(os.path.join(dir, fileName)), sep='\n')
		print("Last Modified Time : ", modificationTime )
		
		print(fileName+os.path.abspath(os.path.join(dir, fileName)), sep='\n'+modificationTime)
		print('\n')'''

def listAllDir(dir):
	rootdir=dir
	print('	File name 				File path')
	for root, dirname, files in os.walk(rootdir):
		for x in files:
			print(x +'			'+root + '\\' + x)
			#print(root + '\\' + x)
			print('\n')

def Delfile(dir):
	os.remove(dir)
	print('The file '+dir+' has been deleted')


if __name__ == '__main__':

	print('Choose one of options\n')
	print('Option 1: Print all the new, modified, deleted files in a particular directory')
	print('Option 2: Print all the new, modified, deleted files in the entire system')
	print('Option 3: Delete a file ')
	option=int(input('Enter the option\n\n'))
	
	if (option == 1):
		FOLDER_PATH=input('Please Enter the file path\n')
		listDir(FOLDER_PATH)

	elif (option == 2):
		listAllDir('D:/')

	elif (option == 3):
		FOLDER_PATH1=input('Please Enter the file path\n')
		Delfile(FOLDER_PATH1)
	else
		print("Please Enter a Valid option")
