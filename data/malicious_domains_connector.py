import requests

URL = "https://www.google.com/images/branding/googlelogo/1x/googlelogo_light_color_272x92dp.png"

# for every domain in the malicous domains list, try to connect to it and download some arbitrary file
# this will not be possible since the file we are trying to download does not exist, we are just interested in capturing dns queries

# 2. download the data behind the URL
response = requests.get(URL)

# 3. Open the response into a new file called instagram.ico
open("google.png", "wb").write(response.content)