from scapy.all import sniff
from scapy.layers import http
from scapy.layers.inet import IP
# r = requests.get('http://stackoverflow.com') # first we try http
import pandas as pd
from sklearn.neighbors import KNeighborsClassifier
import sys
sys.path.insert(0, '/home/mrrobot/TMA/tma_project/test_data/')
import feature_engineering as fe


def tcp_ayikla(paket):
    if not paket.haslayer(http.HTTPRequest):
        return
    http_katmani = paket.getlayer(http.HTTPRequest)

    host = http_katmani.fields['Host'].decode('ASCII')
    path = http_katmani.fields['Path'].decode('ASCII')

    # we can only analyze non https requests
    if 'ocsp' not in host:
        print('-> ' + host + path)

        #Transforming data we get from sniffing
        featured = fe.apply(pd.DataFrame(columns=['url'], data=[host + path]))
        featured_transformed = transform(featured)

        #Prediction
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

#Training the model
def build_model():
    print("Training the model...")
    info_csv = pd.read_csv('../test_data/ready_for_training.csv')
    y = info_csv['type']
    X = info_csv.drop('type', axis=1)
    rfc = KNeighborsClassifier(n_neighbors=3)
    rfc.fit(X, y)
    return rfc


def transform(df):
    code, uniques = df['tld'].factorize()
    df['tld'] = code
    return df


predictor = build_model()
print("System has begun collecting...")

sniff(filter='tcp', prn=tcp_ayikla)