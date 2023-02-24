import os
# Specify the path of the folder to iterate over
folder_path_benign = "./Malicious MS Office documents dataset/benign/benign2"
folder_path_malware = "./malicious3"

import oletools.oleid
from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML
from oletools.olevba import detect_autoexec
import csv
import pandas as pd
import numpy as np
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import confusion_matrix, classification_report
import matplotlib.pyplot as plt
from sklearn import metrics, __all__, datasets


def check(name, j,feature):
    file_path = folder_path_benign+'/'+name
    oid = oletools.oleid.OleID(file_path)
    key_list = {"Run": False, "Call": False, "PowerShell": False, "Hex Strings": False, "Kill": False,"Base64":False}
    output_types = {'AutoExec': False,  'Hex obfuscated': False, 'Base64 obfuscated': False,
                    'Malware': False, 'VBA Stomping': False, 'Executable': False, 'OLE': False, 'IOC': False}
    try:
        indicators = oid.check()
    except:
        return
    if name[0]=='b':
        print("Hello")
        feature["label"].append(0)
    elif name[0]=='m':
        feature["label"].append(1)
    myfile = file_path
    filedata = open(myfile, 'rb').read()
    vbaparser = VBA_Parser(myfile, data=filedata)
    # for i in indicators:
    #     if i.id =="vba":
    #         #print('Indicator id=%s name="%s" type=%s value=%s' % (i.id, i.name, i.type, repr(i.value)))
    if vbaparser.detect_vba_macros():
        # print("entered vba" ,)
        # print('VBA Macros found= ',j, " name= ",name)
        results = vbaparser.analyze_macros()
        for kw_type, keyword, description in results:
            # print('type=%s - keyword=%s - description=%s' % (kw_type, keyword, description))
            check_type(kw_type, output_types,feature)
            check_keyword(keyword, key_list,feature)
            type_set.add(kw_type)
            keyword_set.add(keyword)
        for key, value in key_list.items():
            if value == False:
                feature[key].append(0)
        for key, value in output_types.items():
            if value == False:
                feature[key].append(0)
        # print(keyword_set)
        print(feature)
    else:
        print(' NOT VBA Macros found', j)
        append_zero(feature)

    #print("list = " , key_list , " index = ",i)
        # print('description:', i.description)
        # print('')

def append_zero(feature):
    val = ['AutoExec', 'Hex obfuscated', 'Base64 obfuscated', 'Malware', 'VBA Stomping','Executable', 'OLE', 'IOC',"Run", "Call", "PowerShell", "Hex Strings", "Kill"]
    for i in val:
        feature[i].append(0)



def check_type(type, output_types,feature):
    # Malware_types = {'Dridex': False, 'Ursnif': False, 'Zloader': False, 'Maldoc': False}
    for key, val in output_types.items():
        if (type == key and val != True ) or type == 'Dridex' or type == 'Ursnif' or type == 'Zloader' or type == 'Maldoc' :
            output_types[key] = True
            feature[key].append(1)
            return


def check_keyword(keyword, key_list,feature):
    if keyword == 'Run' or keyword == 'run' and key_list["Run"] != True :
        key_list["Run"] = True
        feature["Run"].append(1)
        return
    if keyword == 'Call' or keyword == 'call' and key_list["Call"] != True:
        key_list["Call"] = True
        feature["Call"].append(1)
        return
    if keyword == 'Hex Strings' and key_list["Hex Strings"] != True:
        key_list["Hex Strings"] = True
        feature["Hex Strings"].append(1)
        return
    if keyword == 'powershell' or keyword == 'PowerShell' or keyword == 'Wscript.Shell' or keyword == 'ShellExecute' and key_list["PowerShell"] != True:
        key_list["PowerShell"] = True
        feature["PowerShell"].append(1)
        return
    if keyword == 'Kill' or keyword == 'kill' and key_list["Kill"] != True:
        key_list["Kill"] = True
        feature["Kill"].append(1)
    if keyword == 'Base64' or keyword == 'Base64 Strings' and key_list["Base64"] != True:
        key_list["Base64"] = True
        feature["Base64"].append(1)
        return


feature = {}
data = set()
type_set = set()
keyword_set = set()

def create_ml_model(feature):
        del feature["filename"]
        df = pd.DataFrame(feature)
        feature_list = df.drop("label",axis=1)
        feature_df = feature_list.to_numpy()
        label = np.stack(df["label"])

        X_train, X_test, y_train, y_test = train_test_split(feature_df, label, test_size=0.1765, random_state=50, stratify=label)
        clf = RandomForestClassifier(n_estimators=100)
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)

        # using metrics module for accuracy calculation
        print("ACCURACY OF THE MODEL: ", metrics.accuracy_score(y_test, y_pred)) #Uncomment for model accuracy.
        return clf, X_test, y_test

# feature["IOC"]=[]
def convert(data):
    # Open a new file in write mode
    with open('data2.csv', 'w', newline='') as file:
        writer = csv.writer(file)

        # Write the header row
        writer.writerow(data.keys())

        # Write the data rows
        for row in zip(*data.values()):
            writer.writerow(row)

def print_result_report(clf, X_test, y_test):
    # We print our results
    sns.set(rc={'figure.figsize': (15, 8)})
    predictions = clf.predict(X_test)
    true_labels = y_test
    cf_matrix = confusion_matrix(true_labels, predictions)
    clf_report = classification_report(true_labels, predictions, digits=5)
    heatmap = sns.heatmap(cf_matrix, annot=True, cmap='Blues', fmt='g',
                          xticklabels=np.unique(true_labels),
                          yticklabels=np.unique(true_labels))
    plt.show()
    print(clf_report)


def run():
    feature["filename"] = []
    feature["Call"] = []
    feature["Run"] = []
    feature["Kill"] = []
    feature["Base64"] = []
    feature["PowerShell"] = []
    feature["Hex Strings"] = []
    feature["AutoExec"] = []
    feature["Hex obfuscated"] = []
    feature["Base64 obfuscated"] = []
    feature["Malware"] = []
    feature["VBA Stomping"] = []
    feature["Executable"] = []
    feature["OLE"] = []
    feature["IOC"] = []
    feature["label"]=[]
    #rename_files()
    i=0
    for filename in os.listdir(folder_path_benign):
     if os.path.isfile(os.path.join(folder_path_benign, filename)):
        #if file == 'doc' or file == 'xls':
        feature["filename"].append(filename)
        check(filename, i,feature)
        i += 1

    for key in feature:
        print("key = ",key," "," len = ",len(feature[key]))
    clf,x,y=create_ml_model(feature)
    #print_result_report(clf,x,y)
    convert(feature)
run()