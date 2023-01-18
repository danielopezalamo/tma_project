import re
import pandas as pd
from urllib.parse import urlparse
from googlesearch import search
from urllib.parse import urlparse
from tld import get_tld

def apply(df):

    #Use of IP or not in domain
    def having_ip_address(url):
        match = re.search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
            '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
            '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
            '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
        if match:
            # print match.group()
            return 1
        else:
            # print 'No matching pattern found'
            return 0
    
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

    #Hostname Length
    def hostname_length(url):
        return len(urlparse(url).netloc)

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

    def tld_length(tld):
        try:
            return len(tld)
        except:
            return -1
    
    
    df['use_of_ip'] = df['url'].apply(lambda i: having_ip_address(i))
    
    df['abnormal_url'] = df['url'].apply(lambda i: abnormal_url(i))
    
    df['google_index'] = df['url'].apply(lambda i: google_index(i))
    
    df['count.'] = df['url'].apply(lambda i: count_dot(i))
    
    df['count-www'] = df['url'].apply(lambda i: count_www(i))
    
    df['count@'] = df['url'].apply(lambda i: count_atrate(i))
    
    df['count_dir'] = df['url'].apply(lambda i: no_of_dir(i))
    
    df['count_embed_domian'] = df['url'].apply(lambda i: no_of_embed(i))
    
    df['short_url'] = df['url'].apply(lambda i: shortening_service(i))
    
    # df['count-https'] = df['url'].apply(lambda i : count_https(i))
    
    # df['count-http'] = df['url'].apply(lambda i : count_http(i))
    
    df['count%'] = df['url'].apply(lambda i : count_per(i))
    
    df['count?'] = df['url'].apply(lambda i: count_ques(i))
    
    df['count-'] = df['url'].apply(lambda i: count_hyphen(i))
    
    df['count='] = df['url'].apply(lambda i: count_equal(i))
    
    df['url_length'] = df['url'].apply(lambda i: url_length(i))
    
    df['hostname_length'] = df['url'].apply(lambda i: hostname_length(i))
    
    df['sus_url'] = df['url'].apply(lambda i: suspicious_words(i))
    
    df['count-digits']= df['url'].apply(lambda i: digit_count(i))
    
    df['count-letters']= df['url'].apply(lambda i: letter_count(i))
    
    df['fd_length'] = df['url'].apply(lambda i: fd_length(i))
    
    #Length of Top Level Domain
    
    df['tld'] = df['url'].apply(lambda i: get_tld(i,fail_silently=True))
    
    df['tld_length'] = df['tld'].apply(lambda i: tld_length(i))
    df.drop(['url'], axis=1, inplace=True)

    return df
