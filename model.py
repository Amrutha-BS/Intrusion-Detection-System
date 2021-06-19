#model
import numpy as np # linear algebra
import pandas as pd # data processing, CSV file I/O (e.g. pd.read_csv)

import sklearn

import time
import sklearn.metrics as m
from sklearn.feature_selection import SelectKBest
from sklearn.feature_selection import f_classif
#from genetic_selection import GeneticSelectionCV
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from sklearn import tree
from sklearn.model_selection import cross_val_score
    
from sklearn.ensemble import AdaBoostClassifier
from sklearn import metrics

global models
models=[]
required_columns=[' Bwd Packet Length Std', ' Fwd IAT Std', ' PSH Flag Count',' Active Min', 'Active Mean', 'Idle Mean', ' Idle Min', ' Flow IAT Max',' min_seg_size_forward', ' Active Max', ' Bwd IAT Mean','Fwd IAT Total', ' Flow Duration', ' Flow IAT Mean','Init_Win_bytes_forward', ' Bwd IAT Min', ' ACK Flag Count',' Active Std', ' Bwd Packet Length Min', ' Fwd IAT Mean','Total Length of Fwd Packets', ' Subflow Fwd Bytes',' Min Packet Length', ' Bwd IAT Max', 'FIN Flag Count', ' Flow IAT Min',' Bwd IAT Std']

def Load_Dataset():
    df1=pd.read_csv("F:/archive/MachineLearningCSV/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")#,nrows = 50000
    df2=pd.read_csv("F:/archive/MachineLearningCSV/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv")
    df3=pd.read_csv("F:/archive/MachineLearningCSV/MachineLearningCVE/Friday-WorkingHours-Morning.pcap_ISCX.csv")
    df4=pd.read_csv("F:/archive/MachineLearningCSV/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv")
    df5=pd.read_csv("F:/archive/MachineLearningCSV/MachineLearningCVE/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv")
    df6=pd.read_csv("F:/archive/MachineLearningCSV/MachineLearningCVE/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv")
    print("Dataset is loaded successfully....")


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
    data = df.copy()
    return data

def preprocessing(data):
    # Check for missing data
    print(f"Missing values: {data.isnull().sum().sum()}")
    # Check for infinite values, replace with NAN so it is easy to remove them
    data.replace([np.inf, -np.inf], np.nan, inplace=True)
    print(f"Missing values: {data.isnull().sum().sum()}")


    deleteCol = []
    for column in data.columns:
        if data[column].isnull().values.any():
            deleteCol.append(column)
    for column in deleteCol:
        data.drop([column],axis=1,inplace=True)
    
    
    deleteCol = []
    for column in data.columns:
        if column == ' Label':
            continue
        elif data[column].dtype==np.object:
            deleteCol.append(column)
    for column in deleteCol:
        data.drop(column,axis=1,inplace=True)
    
    
    for column in data.columns:
        if data[column].dtype == np.int64:
            maxVal = data[column].max()
            if maxVal < 120:
                data[column] = data[column].astype(np.int8)
            elif maxVal < 32767:
                data[column] = data[column].astype(np.int16)
            else:
                data[column] = data[column].astype(np.int32)
            
        if data[column].dtype == np.float64:
            maxVal = data[column].max()
            minVal = data[data[column]>0][column]
            if maxVal < 120 and minVal>0.01 :
                data[column] = data[column].astype(np.float16)
            else:
                data[column] = data[column].astype(np.float32)
 

 
    benign = data[data[' Label'] == 'BENIGN'].sample(frac=0.1).reset_index(drop=True)
    attack = data[data[' Label'] != 'BENIGN']
    data = pd.concat([attack, benign])


    ddos = data[data[' Label'] == 'DDoS'].sample(frac=0.32).reset_index(drop=True)
    attack = data[data[' Label'] != 'DDoS']
    data = pd.concat([attack, ddos])
    #data[' Label'].value_counts()

    dos_hulk = data[data[' Label'] == 'DoS Hulk'].sample(frac=0.1).reset_index(drop=True)
    attack = data[data[' Label'] != 'DoS Hulk']
    data = pd.concat([attack, dos_hulk])

    PortScan = data[data[' Label'] == 'PortScan'].sample(frac=0.32).reset_index(drop=True)
    attack = data[data[' Label'] != 'PortScan']
    data = pd.concat([attack, PortScan])


    y = data[' Label']
    X = data.drop([' Label'],axis=1)

    
    bestfeatures = SelectKBest(score_func=f_classif, k=10)
    fit = bestfeatures.fit(X,y)

    dfscores = pd.DataFrame(fit.scores_)
    dfcolumns = pd.DataFrame(X.columns)
    #concat two dataframes for better visualization 
    featureScores = pd.concat([dfcolumns,dfscores],axis=1)
    featureScores.columns = ['Specs','Score']  #naming the dataframe columns
    #print(featureScores.nlargest(30,'Score'))  #print 10 best features


    feature = pd.DataFrame()
    n = len(featureScores['Specs'])
    for i in featureScores.nlargest(n//2,'Score')['Specs']:
            feature[i] = data[i]
    feature[' Label'] = data[' Label']

    try:
        feature.drop([' Bwd Packet Length Mean'],axis=1,inplace=True)
        feature.drop([' Avg Bwd Segment Size'],axis=1,inplace=True)
        feature.drop(['Bwd Packet Length Max'],axis=1,inplace=True)
        feature.drop([' Packet Length Std'],axis=1,inplace=True)
        feature.drop([' Average Packet Size'],axis=1,inplace=True)
        feature.drop([' Packet Length Mean'],axis=1,inplace=True)
        feature.drop([' Max Packet Length'],axis=1,inplace=True)
        feature.drop([' Packet Length Variance'],axis=1,inplace=True)
        feature.drop([' Idle Max'],axis=1,inplace=True)
        feature.drop([' Fwd IAT Max'],axis=1,inplace=True)
        feature.drop([' Flow IAT Std'],axis=1,inplace=True)
        feature.drop([' Idle Std'],axis=1,inplace=True)
        feature.drop(['Idle Mean'],axis=1,inplace=True)
    except:
         pass

    #print("...........................colums.....................................")
    #print(feature.columns)
    attackType = feature[' Label'].unique()
    feature[' Label'] = feature[' Label'].astype('category')
    feature[' Label'] = feature[' Label'].astype("category").cat.codes

    y = feature[' Label']
    X = feature.drop([' Label'],axis=1)
    print("Preprocessing done Succesfully..............................")
    return X,y


def Train(X,y):
    #Split dataset on train and test
    #from sklearn.model_selection import train_test_split
    train_X, test_X,train_y,test_y=train_test_split(X,y,test_size=0.3, random_state=10)

    #Scalling numerical attributes
    #from sklearn.preprocessing import StandardScaler
    scaler = StandardScaler()

    # extract numerical attributes and scale it to have zero mean and unit variance  
    cols = train_X.select_dtypes(include=['float32','float16','int32','int16','int8']).columns
    sc_train = scaler.fit_transform(train_X.select_dtypes(include=['float32','float16','int32','int16','int8']))
    sc_test = scaler.fit_transform(test_X.select_dtypes(include=['float32','float16','int32','int16','int8']))

    # turn the result back to a dataframe
    train_X = pd.DataFrame(sc_train, columns = cols)
    test_X = pd.DataFrame(sc_test, columns = cols)

    #Dataset Partition
    X_train,X_test,Y_train,Y_test = train_test_split(train_X,train_y,train_size=0.70, random_state=2)

    #Fitting Models
    
    #from sklearn import tree
    #from sklearn.model_selection import cross_val_score
    
    #from sklearn.ensemble import AdaBoostClassifier

    # Train Decision Tree Model
    DTC_Classifier = tree.DecisionTreeClassifier(criterion='entropy', random_state=0)
    DTC_Classifier.fit(X_train, Y_train)

    #ADA_Classifier = AdaBoostClassifier(DTC_Classifier,n_estimators=100,learning_rate=1.5)
    #ADA_Classifier.fit(X_train, Y_train)


    #Evaluate Models
    #from sklearn import metrics
    print("Model trained successfully....................")
    #models = []

    models.append(('Decision Tree Classifier', DTC_Classifier))
    
    #models.append(('ADA_Classifier', ADA_Classifier))
    
    for i, v in models:
        vpred = v.predict(X_train)
        scores = cross_val_score(v, X_train, Y_train, cv=10)
        accuracy = metrics.accuracy_score(Y_train, vpred)
        confusion_matrix = metrics.confusion_matrix(Y_train, vpred)
        classification = metrics.classification_report(Y_train, vpred)
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
    #return model



def Detection(file):
    df=pd.read_csv(file)#,nrows = 50000
    y = df[' Label']
    
    X = df.drop([' Label'],axis=1)
    for i in X.columns:
        if i not in required_columns:
            X=X.drop([i],axis=1)
    #print(X.columns) 
    for i, v in models:
        vpred = v.predict(X)
    for i in range(len(vpred)):
        if vpred[i]!=0:
            print("Line no:",i,"Attack detected")
    print("Detection done..................")
    
    
    

def Intrusion_Detection(file):
    
    data=Load_Dataset()
    X,y=preprocessing(data)
    Train(X,y)
    #file="test2.csv"
    Detection(file)
    print("Finish..............................")
