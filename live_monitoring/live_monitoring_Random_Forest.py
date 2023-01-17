import pyshark
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report,confusion_matrix
import url_columns_compute

# Machine Learning Training
info_csv = pd.read_csv('../datasets/labeled.csv')
y = info_csv['malicious']
X = info_csv.drop('malicious', axis=1)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.30)
rfc = RandomForestClassifier(n_estimators=300)
rfc.fit(X_train, y_train)
print(type(y_train))

def capture_live_packets(network_interface):
    capture = pyshark.LiveCapture(interface=network_interface, display_filter="dns")
    for packet in capture.sniff_continuously():
        prediction_row = url_columns_compute.compute_columns(packet.dns.qry_name)
        rfc_pred = rfc.predict(prediction_row)
        print('-------------------------')
        print(packet.dns.qry_name)
        print(rfc_pred)
        print('-------------------------')
    

capture_live_packets('Ethernet')
