from http.client import responses
from imghdr import tests
from linecache import cache
from xml.sax.saxutils import escape

import requests
import fire
import json

from Tools.scripts.eptags import treat_file
from requests_toolbelt import MultipartEncoder

SERVER = "http://127.0.0.1:8000"
APPNAME = ''
API_KEY = ''
HASH = ''

def start(appname, api_key):
    global APPNAME, API_KEY
    APPNAME = appname
    API_KEY = api_key
    data = upload()
    print("Start Static Analysis")
    scan(data)
    pdf()
    json_report()
    print("Start Dynamic Analysis")
    start_dynamic_analysis()
    set_proxy()

def upload():
    print(f"upload {APPNAME}")
    try :
        multipart_data = MultipartEncoder(fields={'file': (APPNAME, open(APPNAME, 'rb'), 'application/octet-stream')})
        headers = {'Content-Type': multipart_data.content_type, 'Authorization': API_KEY}
        response = requests.post(SERVER + '/api/v1/upload', data=multipart_data, headers=headers)
        if response.status_code != 200:
            print(f"failed to upload {APPNAME} : {response.content}")
            exit(1)
        global HASH
        HASH = response.json()['hash']
        print(f"Successfully Upload File : APK : {APPNAME}, Hash : {HASH}")
        return response.text
    except Exception as e:
        print("ERROR " + str(e))

def scan(data):
    print("Scanning APK Hash : " + HASH)
    headers = {'Authorization': API_KEY}
    try:
        APK_info = json.loads(data)
        response = requests.post(SERVER + '/api/v1/scan', data=APK_info, headers=headers)
        if response.status_code != 200:
            print(f"failed to scan {APPNAME} : {response.content}")
            exit(1)
        print(f"Successfully scan File")
    except Exception as e :
        print("ERROR " + str(e))
        exit(1)


def pdf():
    print("Generate static analysis report to PDF")
    headers = {'Authorization': API_KEY}
    data = {"hash": HASH}
    try :
        response = requests.post(SERVER + '/api/v1/download_pdf', data=data, headers=headers, stream=True)
        if response.status_code != 200:
            print(f"failed generating static analysis report pdf : {response.content}")
            exit(1)
        with open(f"{APPNAME}_{HASH}_static.pdf", "wb") as f:
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    f.write(chunk)
        print(f"Static PDF saved as {APPNAME}_{HASH}_static.pdf")
    except Exception as e :
        print("ERROR " + str(e))
        exit(1)

def json_report():
    print("Generate static analysis report to JSON")
    headers = {'Authorization': API_KEY}
    data = {"hash": HASH}
    try :
        response = requests.post(SERVER + '/api/v1/report_json', data=data, headers=headers, stream=True)
        if response.status_code != 200:
            print(f"failed generating static analysis report json : {response.content}")
            exit(1)
        with open(f"{APPNAME}_{HASH}_static.json", "wb") as f:
            f.write(response.content)
        print(f"Static json saved as {APPNAME}_{HASH}_static.json")
    except Exception as e :
        print("ERROR " + str(e))
        exit(1)

def start_dynamic_analysis():
    headers = {'Authorization': API_KEY}
    data = {"hash": HASH}
    try :
        response = requests.post(SERVER + '/api/v1/dynamic/start_analysis', data=data, headers=headers)
        if response.status_code != 200:
            print(f"failed to start analysis : {response.content}")
            exit(1)
        print(f"Successfully Start Dynamic Analysis")
    except Exception as e :
        print("ERROR " + str(e))

def set_proxy():
    headers = {'Authorization': API_KEY}
    set = {'action': 'set'}
    try :
        response = requests.post(SERVER + '/api/v1/android/global_proxy', data=set, headers=headers)
        if response.status_code != 200:
            print(f"failed to set proxy : {response.content}")
            exit(1)
        print(f"Successfully Set Proxy")
    except Exception as e :
        print("ERROR " + str(e))

def active_activity():
    try :
        headers = {'Authorization': API_KEY}
        test = {'test' : }





if __name__ == "__main__" :
    fire.Fire(start)