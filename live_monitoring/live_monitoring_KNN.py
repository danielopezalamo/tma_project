from scapy.all import sniff
from scapy.layers import http
from scapy.layers.inet import IP
# r = requests.get('http://stackoverflow.com') # first we try http
import pandas as pd
from sklearn.neighbors import KNeighborsClassifier
import test_data.feature_engineering as fe


def tcp_ayikla(paket):
    if not paket.haslayer(http.HTTPRequest):
        return
    http_katmani = paket.getlayer(http.HTTPRequest)

    host = http_katmani.fields['Host'].decode('ASCII')
    path = http_katmani.fields['Path'].decode('ASCII')

    if 'ocsp' not in host:
        print('-> ' + host + path)
        print('# Prediction: ')

        #Transforming data we get from sniffing
        featured = fe.apply(pd.DataFrame(columns=['url'], data=[host + path]))
        featured_transformed = transform(featured)

        #Prediction
        out = predictor.predict(featured_transformed)[0]
        if out == 0:
            print("!> Phishing")
        elif out == 1:
            print("!> Benign")
        elif out == 2:
            print("!> Defacement")
        elif out == 3:
            print("!> Malware")
        else:
            print("Unkown")
    else:  # this are ocsp requests, we are handling with encrypted data
        print('-> Protected by https.')

#Training the model
def build_model():
    print("Training the model...")
    info_csv = pd.read_csv('../test_data/ready_for_training.csv')
    y = info_csv['type']
    X = info_csv.drop('type', axis=1)
    rfc = KNeighborsClassifier(n_neighbors=15)
    rfc.fit(X, y)
    return rfc


def transform(df):
    code, uniques = df['tld'].factorize()
    df['tld'] = code
    return df


predictor = build_model()
print("System has begun collecting...")

sniff(filter='tcp', prn=tcp_ayikla)


