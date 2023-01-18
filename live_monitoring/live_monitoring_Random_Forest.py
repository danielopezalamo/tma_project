import pyshark
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report,confusion_matrix
import test_data.feature_engineering as fe

# Machine Learning Training
print('Training...')
info_csv = pd.read_csv('../test_data/ready_for_training.csv')
y = info_csv['type']
X = info_csv.drop('type', axis=1)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.30)
rfc = RandomForestClassifier(n_estimators=300)
rfc.fit(X_train, y_train)
print("Finished!")

def capture_live_packets(network_interface):
    capture = pyshark.LiveCapture(interface=network_interface, display_filter="http")
    print("Collecting http packets...")
    for packet in capture.sniff_continuously():
        url = packet.http.get_field('http.request.full_uri')
        if url:
            df = pd.DataFrame(columns = ['url'])
            df['url'] =[url]
            df = fe.apply(df)
            print('Predicting: %s' %url)
            rfc_pred = rfc.predict(df)
            print('-------------------------')
            print(url)
            print(rfc_pred)
            print('-------------------------')
        
        

capture_live_packets('Ethernet')


