# import pyshark
# import pandas as pd
# import numpy as np
# import matplotlib.pyplot as plt
# from sklearn.model_selection import train_test_split
# from sklearn.tree import DecisionTreeClassifier
# from sklearn.ensemble import RandomForestClassifier
# from sklearn.metrics import classification_report,confusion_matrix
# import url_columns_compute

# # Machine Learning Training
# info_csv = pd.read_csv('../datasets/labeled.csv')
# y = info_csv['malicious']
# X = info_csv.drop('malicious', axis=1)
# X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.30)
# rfc = RandomForestClassifier(n_estimators=300)
# rfc.fit(X_train, y_train)
# print(type(y_train))

# def capture_live_packets(network_interface):
#     capture = pyshark.LiveCapture(interface=network_interface, display_filter="dns")
#     for packet in capture.sniff_continuously():
#         prediction_row = url_columns_compute.compute_columns(packet.dns.qry_name)
#         rfc_pred = rfc.predict(prediction_row)
#         print('-------------------------')
#         print(packet.dns.qry_name)
#         print(rfc_pred)
#         print('-------------------------')
    

# capture_live_packets('Ethernet')

from scapy.all import IP, sniff
from scapy.layers import http
# import requests
# r = requests.get('http://stackoverflow.com') # first we try http
# r.url # check the actual URL for the site
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report,confusion_matrix
import sys
sys.path.insert(0, 'C:/Users/danie/Desktop/tma_project/test_data')
from feature_engineering import apply

def tcp_ayikla(paket):
    
    if not paket.haslayer(http.HTTPRequest):
        return
    http_katmani = paket.getlayer(http.HTTPRequest)

    ip_katmani = paket.getlayer(IP)
    
    host = http_katmani.fields['Host'].decode('ASCII')
    path = http_katmani.fields['Path'].decode('ASCII')

    if 'ocsp' not in host:
        print('-> '+ host + path)
        featured = apply(pd.DataFrame(columns=['url'], data=[host+path]))
        featured_transformed = transform(featured)
        out = predictor.predict(featured_transformed)[0]
        if out == 0:
            print("# Prediction: Phishing")
        elif out == 3:
            print("# Prediction: Benign")
        elif out == 1:
            print("# Prediction: Defacement")
        elif out == 2:
            print("# Prediction: Malware")
        else:
            print("Unkown")
        print()

def build_model():
    print("Training the model...")
    info_csv = pd.read_csv('../test_data/ready_for_training.csv')
    y = info_csv['type']
    X = info_csv.drop('type', axis=1)
    rfc = RandomForestClassifier(n_estimators=100)
    rfc.fit(X, y)
    return rfc

def transform(df):
    code, uniques = df['tld'].factorize()
    df['tld'] = code
    return df

predictor = build_model()
print("System has begun collecting...")

sniff(filter='tcp', prn=tcp_ayikla)