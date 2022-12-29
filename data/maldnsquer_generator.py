import requests
import sys

# for every domain in the malicous domains list, try to connect to it and download some arbitrary file
# this will not be possible since the file we are trying to download does not exist, we are just interested in capturing dns queries

n = int(sys.argv[1])
targets = []

with open("malicious_domains.txt", "r") as file:
    if n != -1:
        for i in range(n):
            targets += [file.readline()]
    else:
        targets = file.readlines()

for domain in targets:
    print(f"Downloading https://{domain[:-1]}/malware")
    try:
        response = requests.get(f'https://{domain[:-1]}/malware')
    except:
        print("Could download specified file.\n")