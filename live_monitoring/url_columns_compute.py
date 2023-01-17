import requests
import pandas as pd
import re
from urllib.parse import urlparse
from googlesearch import search
from urllib.parse import urlparse
from tld import get_tld
import os.path
import sys
import socket
import time
import ipinfo as ip

#Use of IP or not in domain
def validate_ip(s):
    if ':' in s:
        port = s.split(':')
        s = s[:-len(port)-1]    
    
    if s.count('.') != 3: 
        return False
    ip_list = list(map(str,s.split('.')))
    
    # check range of each number between periods  
    try:
        for element in ip_list:
            if int(element) < 0 or int(element) > 255 or (element[0]=='0' and len(element)!=1):
                return False
    except:
        return False
    return True

def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0

def google_index(url):
    site = search(url, 5)
    return 1 if site else 0

def count_dot(url):
    count_dot = url.count('.')
    return count_dot

def count_www(url):
    url.count('www')
    return url.count('www')

def count_atrate(url):     
    return url.count('@')

def no_of_dir(url):
    urldir = urlparse(url).path
    return urldir.count('/')

def no_of_embed(url):
    urldir = urlparse(url).path
    return urldir.count('//')

def shortening_service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)
    if match:
        return 1
    else:
        return 0
    
def count_https(url):
    return url.count('https')

def count_http(url):
    return url.count('http')

def count_per(url):
    return url.count('%')

def count_ques(url):
    return url.count('?')

def count_hyphen(url):
    return url.count('-')

def count_equal(url):
    return url.count('=')

def url_length(url):
    return len(str(url))

def hostname_length(domain_name):
    return len(domain_name)

def suspicious_words(url):
    match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr',
                      url)
    if match:
        return 1
    else:
        return 0

def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits

def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters

#First Directory Length
def fd_length(url):
    urlpath= urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0

#Top level domain
def tld_length(tld):
    try:
        return len(tld)
    except:
        return -1


def port_present(domain):
    return ':' in domain

def get_domain_name(url):
    if url[:4] != "http":
        url = "http://" + url
    domain = urlparse(url).netloc
    if port_present(domain):
        return domain.split(':')[0]
    return domain

def get_port(url):
    domain = urlparse(url).netloc
    if port_present(domain):
        return int(domain.split(':')[1])
    else:
        return 80

def compute_columns(url):
    df = pd.DataFrame(
        columns=[
            'dport',\
            'having_ip_address', \
            'hostname_length', 'count_dir', 'count-www',\
            'fd_length', 'url_length', 'abnormal_url', \
            'count-http', 'count-letters', 'tld-length',\
            'count.', 'count-digits', 'count-', 'count=',\
            'count-https', 'sus_url', 'count?', 'count%', \
            'short_url', 'count@', 'count_embed_domain'
        ]
    )

    domain_name = get_domain_name(url)
    try:
        new = [get_port(url), validate_ip(domain_name),\
        hostname_length(domain_name), no_of_dir(url), count_www(url), fd_length(url), \
        url_length(url), abnormal_url(url), count_http(url), letter_count(url), \
        tld_length(get_tld(url,fail_silently=True)), count_dot(url), digit_count(url),\
        count_hyphen(url), count_equal(url), count_https(url), suspicious_words(url),\
        count_ques(url), count_per(url), shortening_service(url), count_atrate(url), \
        no_of_embed(url)]
        df.loc[len(df)] = new

    except Exception as e:
        print(e)
    
    return df

if __name__ == "__main__":

    domains_database = pd.read_csv('data_set.csv')

    df = pd.DataFrame(columns=['url', 'domain_name', 'dport',\
                            'having_ip_address', \
                            'hostname_length', 'count_dir', 'count-www',\
                            'fd_length', 'url_length', 'abnormal_url', \
                            'count-http', 'count-letters', 'tld-length',\
                            'count.', 'count-digits', 'count-', 'count=',\
                            'count-https', 'sus_url', 'count?', 'count%', \
                            'short_url', 'count@', 'count_embed_domain',\
                            'malicous'])
    extra = 0
    start = time.time()
    i = 0
    for row in domains_database.iterrows():
        url = row[1][0]
        out = row[1][1]
        domain_name = get_domain_name(url)

        try:
            new = [url, domain_name, get_port(url), validate_ip(domain_name),\
            hostname_length(domain_name), no_of_dir(url), count_www(url), fd_length(url), \
            url_length(url), abnormal_url(url), count_http(url), letter_count(url), \
            tld_length(get_tld(url,fail_silently=True)), count_dot(url), digit_count(url),\
            count_hyphen(url), count_equal(url), count_https(url), suspicious_words(url),\
            count_ques(url), count_per(url), shortening_service(url), count_atrate(url), \
            no_of_embed(url), out]
        except Exception as e:
            print(e)
            i += 1
            continue

        df.loc[len(df)] = new
        i += 1
        print(f'{i} of {len(domains_database)}.\n')
        df.to_csv(f'results_2.csv', index=False)   

    end = time.time()
    print(f'\ntotal time: {end-start}')
    print(f'\naverage per url: {(end-start)/len(domains_database)}')
        
    