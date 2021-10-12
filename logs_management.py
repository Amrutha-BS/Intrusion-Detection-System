import os 
import time
import glob

#FOLDER_PATH = r'C:/Users/DELL/OneDrive/Desktop/frontend'

def listDir(dir):
	fileNames = os.listdir(dir)

	for fileName in fileNames:
		modTimesinceEpoc = os.path.getmtime(fileName)
		modificationTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(modTimesinceEpoc))
		
		print('File Name: ' + fileName)
		print('Folder Path: ' + os.path.abspath(os.path.join(dir, fileName)), sep='\n')
		print("Last Modified Time : ", modificationTime )
		print('\n')

def listAllDir(dir):
	rootdir=dir
	for root, dirname, files in os.walk(rootdir):
		for x in files:
			'''modTimesinceEpoc = os.path.getmtime(x)
			modificationTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(modTimesinceEpoc))'''
			print(root + '\\' + x)
			print('\n')


if __name__ == '__main__':

	print('Choose one of options\n')
	print('Option 1: Print all the new, modified, deleted files in a particular directory')
	print('Option 2: Print all the new, modified, deleted files in the entire system')
	option=int(input('Enter the option\n\n'))
	
	if (option == 1):
		FOLDER_PATH=input('Please Enter the file path\n')
		listDir(FOLDER_PATH)

	elif (option == 2):
		listAllDir('D:/')

	else: 
		print('Invalid option')

