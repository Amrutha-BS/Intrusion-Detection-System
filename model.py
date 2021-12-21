#model
import numpy as np # linear algebra
import pandas as pd # data processing, CSV file I/O (e.g. pd.read_csv)

import sklearn

import time
import sklearn.metrics as m
from sklearn.feature_selection import SelectKBest
from sklearn.feature_selection import f_classif

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from sklearn import tree
from sklearn.model_selection import cross_val_score
    
from sklearn import metrics

from sklearn.svm import SVC

from sklearn import tree
from sklearn.model_selection import cross_val_score
from sklearn import metrics

# importing Label encoder from sklearn 
from sklearn.preprocessing import LabelEncoder 

# Declaring and initilaizing Global variables
global models
models=[]

global required_columns
required_columns=[]

global d
d={}

global d2
d2={}

global DTC_Classifier_1
DTC_Classifier_1=tree.DecisionTreeClassifier(criterion='entropy', random_state=0)

global DTC_Classifier_2
DTC_Classifier_2=tree.DecisionTreeClassifier(criterion='entropy', random_state=0)

global DTC_Classifier_3
DTC_Classifier_3=tree.DecisionTreeClassifier(criterion='entropy', random_state=0)

#required_columns=[' Bwd Packet Length Std', ' Fwd IAT Std', ' PSH Flag Count',' Active Min', 'Active Mean', 'Idle Mean', ' Idle Min', ' Flow IAT Max',' min_seg_size_forward', ' Active Max', ' Bwd IAT Mean','Fwd IAT Total', ' Flow Duration', ' Flow IAT Mean','Init_Win_bytes_forward', ' Bwd IAT Min', ' ACK Flag Count',' Active Std', ' Bwd Packet Length Min', ' Fwd IAT Mean','Total Length of Fwd Packets', ' Subflow Fwd Bytes',' Min Packet Length', ' Bwd IAT Max', 'FIN Flag Count', ' Flow IAT Min',' Bwd IAT Std']

__author__='''
# =========================================================================|
#   NIDS has begun
# =========================================================================|
'''

#Function to remove Infinite values from data frame
def removeInf(df):
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    deleteCol = []
    for column in df.columns:
        if df[column].isnull().values.any():
            deleteCol.append(column)
        
    for column in deleteCol:
        df.drop([column],axis=1,inplace=True)
    return df

   
#Function to load the dataset to build the model   
def load_dataset():
    
    print()
    print(__author__)
    print()
    print()
    print('=============================================  PHASE - 1  ================================================')
    print()
    print('============================== The model building has begun  ==============================')
    
    ###### 2017 CIC-IDS DATASET ######
    df1=pd.read_csv("F:/archive/MachineLearningCSV/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")#,nrows = 50000
    df_dos1=pd.read_csv("F:/archive/MachineLearningCSV/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")#,nrows = 50000
    df_dos2=pd.read_csv("F:/archive/MachineLearningCSV/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv")
   
    df2=pd.read_csv("F:/archive/MachineLearningCSV/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv")
    df3=pd.read_csv("F:/archive/MachineLearningCSV/MachineLearningCVE/Friday-WorkingHours-Morning.pcap_ISCX.csv")
    df4=pd.read_csv("F:/archive/MachineLearningCSV/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv")
    df5=pd.read_csv("F:/archive/MachineLearningCSV/MachineLearningCVE/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv")
    df6=pd.read_csv("F:/archive/MachineLearningCSV/MachineLearningCVE/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv")
    print("\nDataset is loaded successfully....\n")


    #Concatenating all the dataset files into one
    df = pd.concat([df1,df2])
    del df1,df2
    df = pd.concat([df,df3])
    del df3
    df = pd.concat([df,df4])
    del df4
    df = pd.concat([df,df5])
    del df5
    df = pd.concat([df,df6])
    del df6
    df1_dos = pd.concat([df_dos1,df_dos2])
    del df_dos1,df_dos2
    df = removeInf(df)
    df1_dos = removeInf(df1_dos)
    return df,df1_dos
    
    
def preprocessing(df,df1_dos):       
    #Split dataset on train and test
    from sklearn.model_selection import train_test_split
    train, test=train_test_split(df,test_size=0.3, random_state=10)
    dos_train, dos_test=train_test_split(df1_dos,test_size=0.2, random_state=10)
    
    print(type(train),type(test))
    #exit(0)
    # Packet Attack Distribution
    print('============================== The Details of Dataset being used  ==============================\n')
    
    print("Details of Train set:\n")
    print(train[' Label'].value_counts())
    
    print("Details of Test set:\n")
    print(test[' Label'].value_counts())
    
    print()
    print("\n")
    
    #Scalling numerical attributes
    from sklearn.preprocessing import StandardScaler
    scaler = StandardScaler()
    
    #Normalisation
    # extract numerical attributes and scale it to have zero mean and unit variance  
    
    cols = train.select_dtypes(include=['float64','int64']).columns
    sc_train = scaler.fit_transform(train.select_dtypes(include=['float64','int64']))
    sc_test = scaler.fit_transform(test.select_dtypes(include=['float64','int64']))
    sc_dos = scaler.fit_transform(dos_train.select_dtypes(include=['float64','int64']))
    
    # turn the result back to a dataframe
    sc_traindf = pd.DataFrame(sc_train, columns = cols)
    sc_testdf = pd.DataFrame(sc_test, columns = cols)
    sc_dosdf = pd.DataFrame(sc_dos, columns = cols)
    
    train_Y1=[]
    test_Y1=[]
    dos_Y=[]
    
    for i in train[' Label']:
        if i=="BENIGN":
            train_Y1.append(1)
        else:
            train_Y1.append(0)
            
            
    for i in test[' Label']:
        if i=="BENIGN":
            test_Y1.append(1)
        else:
            test_Y1.append(0)
   
            
    train_Y1 = np.array(train_Y1)
    test_Y1 = np.array(test_Y1)
        
    
    #Encoding Values
    # creating instance of labelencoder
    label_encoder = LabelEncoder()
    
    # Assigning numerical values and storing in another column
    train_Y2= label_encoder.fit_transform(train[' Label'])

    n = train_Y2
    m = label_encoder.inverse_transform(train_Y2)

    test_Y2= label_encoder.fit_transform(test[' Label'])

    l=len(m)
    #d={}
    for i in range(l):
        if n[i] not in d:
            d[n[i]]=m[i]
    for i in range(l):
        if m[i] not in d2:
            d2[m[i]]=n[i]
            
    print("dict",d)
    print("#####################")
    print("d2",d2)
    #{0:"BENIGN",9:"PortScan".........}
    #Key = Number, Value = Attack classification
    
    for i in dos_train[' Label']:
        if i=="BENIGN":
            dos_Y.append(1)
        else:
            dos_Y.append(d2[i])
            
    train_X = sc_traindf
    test_X = sc_testdf
    dos_X =  sc_dosdf
    
    #The best 38 features/columns
    bestfeatures = SelectKBest(score_func=f_classif, k=10)
    fit = bestfeatures.fit(train_X,train_Y2)

    dfscores = pd.DataFrame(fit.scores_)
    dfcolumns = pd.DataFrame(train_X.columns)
    
    #concat two dataframes for better visualization 
    featureScores = pd.concat([dfcolumns,dfscores],axis=1)
    featureScores.columns = ['Specs','Score']  #naming the dataframe columns
    

    feature = pd.DataFrame()
    dos_feature = pd.DataFrame()
    
    n = len(featureScores['Specs'])#76
    for i in featureScores.nlargest(n//2,'Score')['Specs']:
        feature[i] = train_X[i]
        dos_feature[i] = dos_X[i]
       
    
    for i in feature.columns:
        required_columns.append(i)

    train_X = feature
    dos_X = dos_feature
    
    print('\n============================== Preprocessing is done successfully  ==============================\n')
    return train_X,train_Y1,train_Y2,test_X,test_Y1,test_Y2,dos_X,dos_Y
    
    
def train_model(train_X,train_Y1,train_Y2, dos_X, dos_Y):
    #Dataset Partition
    X1_train,X1_test,Y1_train,Y1_test = train_test_split(train_X,train_Y1,train_size=0.70, random_state=2)

    X2_train,X2_test,Y2_train,Y2_test = train_test_split(train_X,train_Y2,train_size=0.70, random_state=2)

    #Fitting Models
    
    # Train Decision Tree Model
    #DTC_Classifier = tree.DecisionTreeClassifier(criterion='entropy', random_state=0)
    DTC_Classifier_1.fit(X1_train, Y1_train)
    
    DTC_Classifier_2.fit(X2_train, Y2_train)
    
    DTC_Classifier_3.fit(dos_X, dos_Y)

    #Evaluate Models
    #from sklearn import metrics

    #models = []
    
    models.append(('Decision Tree Classifier-1', DTC_Classifier_1))
    models.append(('Decision Tree Classifier-2', DTC_Classifier_2))
    
    for i, v in models:
        if i=="Decision Tree Classifier-1":
            X_train,Y_train = X1_train,Y1_train
        else:
            X_train,Y_train = X2_train,Y2_train
        
        scores = cross_val_score(v, X_train, Y_train, cv=10)
        #print(type(scores))
        accuracy = metrics.accuracy_score(Y_train, v.predict(X_train))
        confusion_matrix = metrics.confusion_matrix(Y_train, v.predict(X_train))
        classification = metrics.classification_report(Y_train, v.predict(X_train))
        print()
        print('============================== {} Model Evaluation =============================='.format(i))
        print()
        print ("Cross Validation Mean Score:" "\n", scores.mean())
        print()
        print ("Model Accuracy:" "\n", accuracy)
        print()
        print("Confusion matrix:" "\n", confusion_matrix)
        print()
        print("Classification report:" "\n", classification) 
        print()
           
        
    #Validate Models
    for i, v in models:
        if i=="Decision Tree Classifier-1":
            X_test,Y_test = X1_test,Y1_test
        else:
            X_test,Y_test = X2_test,Y2_test
        accuracy = metrics.accuracy_score(Y_test, v.predict(X_test))
        confusion_matrix = metrics.confusion_matrix(Y_test, v.predict(X_test))
        classification = metrics.classification_report(Y_test, v.predict(X_test))
        print()
        print('============================== {} Model Test Results =============================='.format(i))
        print()
        print ("Model Accuracy:" "\n", accuracy)
        print()
        print("Confusion matrix:" "\n", confusion_matrix)
        print()
        print("Classification report:" "\n", classification) 
        print()  

    
#Function to test the built model    
def testing_model(test_X,test_Y1,test_Y2):	
    # PREDICTING FOR TEST DATA

    test_data = pd.DataFrame()
    #test_data2 = pd.DataFrame()
    
    for i in required_columns:
        test_data[i] = test_X[i]
        #test_data2[i] = test_X2[i]
    
        
    test_data = removeInf(test_data)  
    #test_data2 = removeInf(test_data2)  
    Hybrid_DTC(test_data,test_data,test_Y1,test_Y2)
    ''' 
    #Accuracy   
    for j, v in models:
        if j=="Decision Tree Classifier-1":
            accuracy1 = metrics.accuracy_score(test_Y1, v.predict(test_data))
        else:
            accuracy2 = metrics.accuracy_score(test_Y2, v.predict(test_data))
            
    print()
    print()
    
    print('\n============================== The Accuracy  ==============================\n')
    
    print("DTC-1 Accuracy : ",accuracy1)
    print("DTC-2 Accuracy : ",accuracy2)
    '''
#d={0:"BENIGN",2:"Dos Hulk"...}
#d2={"BENIGN":0,"Dos Hulk":2,...}
def Hybrid_DTC(test_data1,test_data2,Y1,Y2):
   
    
    #printng accuracy,detail report 
    vpred_1=DTC_Classifier_1.predict(test_data1)
    vpred_2=DTC_Classifier_2.predict(test_data2)
    dos_l=[]
    #print(vpred_2)
    #print("done-1",type(test_data2))
    for i in range(len(vpred_2)):
        if vpred_2[i] == 2 or vpred_2[i] == 4 or vpred_2[i] == 5 or vpred_2[i] == 6 or vpred_2[i] == 3 or vpred_2[i] == 1 :
            dos_l.append(i)
    
    #print("donee")    
    dos_data = test_data2.iloc[dos_l]
    
    #print("done-2")        
    vpred_3=DTC_Classifier_3.predict(dos_data)
    #print("done-3") 
    k=0
    for i in range(len(vpred_2)):
        if vpred_2[i]==2 or vpred_2[i]==4 or vpred_2[i]==5 or vpred_2[i]==6 or vpred_2[i]==3 or vpred_2[i]==1 :
            vpred_2[i] = vpred_3[k]
            k+=1
    #print("done-4") 
    '''
    print("vpred_1\n")
    print(vpred_1)
    
    print("vpred_2\n")
    print(vpred_2)
    '''
    l=len(vpred_1)
    
    if Y1!=[]:
        print('========================= The accuracy of the classfication[Benign/Malicious] of traffic in the input file ========================')
        print("accuracy of the input traffic given",metrics.accuracy_score(Y1, vpred_1))
        
        print('========================= The accuracy of the classfication[Benign/Type Malicious attack] of traffic in the input file ======================')
        print("accuracy of the input traffic given",metrics.accuracy_score(Y2, vpred_2))
            
    print('\n============================== The detailed results  ==============================\n')
    
    for i in range(l):
        if vpred_1[i] == 0:
            if d[vpred_2[i]]!='BENIGN':
                print("Line no:",i,": ","Attack detected ------ ",d[vpred_2[i]])
            else:
                print("Line no:",i,": ","Attack detected ------ [New type of Attack]")
    return 0        
      
         
  
        
#Function to predict and detect intrusion in input file
def detection(file):
    df=pd.read_csv(file)#,nrows = 50000
    
    #Remove inf values and replace it with nan
    df = removeInf(df)
    
    Y1=[]
    Y2=[]
    
    if ' Label' in df.columns:
        vals=df[' Label'].values
        d2={}
        for i in d:
            d2[d[i]]=i
        #print("vals",vals)    
        for i in range(len(df[' Label'])):
            if vals[i]=="BENIGN":
                Y1.append(1)
            else:
                Y1.append(0)
        #print("Y1",Y1)        
        for i in range(len(df[' Label'])):
            Y2.append(d2[vals[i]])
        #print("Y2",Y2)
    
    #test_Y1 = pd.DataFrame(Y1, columns = [' Label'])
    #test_Y2 = pd.DataFrame(Y2, columns = [' Label'])
    
    #Normalisation
    
    scaler = StandardScaler()
    cols = df.select_dtypes(include=['float64','int64']).columns
    data = scaler.fit_transform(df.select_dtypes(include=['float64','int64']))
    
    data_df = pd.DataFrame(data, columns = cols)
   
    #data_df=df
    '''
    ds1 = scaler.fit_transform(test_Y1.select_dtypes(include=['float64','int64']))
    ds2 = scaler.fit_transform(test_Y2.select_dtypes(include=['float64','int64']))
    
    print(Y1,Y2)
    
    df = pd.DataFrame(data, columns = cols)
    Y1 = pd.DataFrame(ds1, columns = [' Label'])
    Y2 = pd.DataFrame(ds2, columns = [' Label'])
    '''
    test_data1 = pd.DataFrame()
    test_data2 = pd.DataFrame()
    
    #if d3=={}:
    #    df_new = df.rename(columns=d3)
    
    for i in required_columns:
        if i not in data_df.columns:
            print("The required column ",i,"is missing\n")
            return 1 
        else:
            test_data1[i]=df[i]
            test_data2[i]=data_df[i]
            

    #print("required_columns",len(required_columns))
    #print("test_data",len(test_data.columns))
    #print("test_data",len(test_data))
    print()
    
    print("All the required columns are present\n")
    print("------------------------------------")  
    
    return Hybrid_DTC(test_data1,test_data2,Y1,Y2)    
    #printng accuracy,detail report  
    

#The main function        
def Intrusion_Detection(file):
    
    data,data_dos=load_dataset()
    train_X,train_Y1,train_Y2,test_X,test_Y1,test_Y2,dos_X,dos_Y=preprocessing(data,data_dos)
    
    train_model(train_X,train_Y1, train_Y2, dos_X, dos_Y)
    
    #print("Testing the model\n")
    
    #testing_model(test_X,test_Y1,test_Y2)
    
    print("\n")
    
    print('=============================================  PHASE - 2  ================================================')
    
    if (detection(file)):
        print("\n==================The NIDS has been stopped due to missing features===============\n")
        print("Please enter values for all the following features/columns",required_columns)
        return 
        
    print()
    print('============================== Finish  ==============================')
    
    
#file="F:/archive/MachineLearningCSV/MachineLearningCVE/test_file.csv"      
#intrusion_detection(file)        

       

       
     
