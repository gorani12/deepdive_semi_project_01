from http.client import responses

import requests
import fire
import json

from requests_toolbelt import MultipartEncoder

SERVER = ''
APPNAME = ''
API_KEY = ''
ADB_IDENTIFIER = ''
HASH = ''
DATA_HASH = ''
API_KEY_HEADERS = None


def start(server, appname, api_key, identifier):
    global SERVER, APPNAME, API_KEY, ADB_IDENTIFIER, API_KEY_HEADERS, DATA_HASH
    SERVER = server
    APPNAME = appname
    API_KEY = api_key
    ADB_IDENTIFIER = {'identifier': identifier}
    API_KEY_HEADERS = {'Authorization': api_key}
    data = upload()
    print("Start Static Analysis")
    scan(data)
    static_pdf()
    static_json()
    print("Start Dynamic Analysis")
    mobsfy()
    start_dynamic_analysis()
    set_proxy()
    test_activity("exported")
   # test_activity("activity")
    tls_test()
    dynamic_json()

def upload():
    global HASH, DATA_HASH
    print(f"upload {APPNAME}")
    multipart_data = MultipartEncoder(fields={'file': (APPNAME, open(APPNAME, 'rb'), 'application/octet-stream')})
    headers = {'Content-Type': multipart_data.content_type, 'Authorization': API_KEY}
    response = requests.post(SERVER + '/api/v1/upload', data=multipart_data, headers=headers)
    if response.status_code != 200:
        print(f"failed to upload {APPNAME} : {response.content}")
        exit(1)
    HASH = response.json()['hash']
    DATA_HASH = {"hash": HASH}
    print(f"Successfully Upload File : APK : {APPNAME}, Hash : {HASH}")
    return response.text


def scan(data):
    global DATA_HASH
    print("Scanning APK Hash : " + HASH)
    apk_info = json.loads(data)
    response = requests.post(SERVER + '/api/v1/scan', data=apk_info, headers=API_KEY_HEADERS)
    if response.status_code != 200:
        print(f"failed to scan {APPNAME} : {response.content}")
        exit(1)
    print(f"Successfully scan File")


def static_pdf():
    print("Generate static analysis report to PDF")
    response = requests.post(SERVER + '/api/v1/download_pdf', data=DATA_HASH, headers=API_KEY_HEADERS, stream=True)
    if response.status_code != 200:
        print(f"failed generating static analysis report pdf : {response.content}")
        exit(1)
    with open(f"{APPNAME}_{HASH}_static.pdf", "wb") as f:
        for chunk in response.iter_content(chunk_size=1024):
            if chunk:
                f.write(chunk)
    print(f"Static PDF saved as {APPNAME}_{HASH}_static.pdf")


def static_json():
    print("Generate static analysis report to JSON")
    response = requests.post(SERVER + '/api/v1/report_json', data=DATA_HASH, headers=API_KEY_HEADERS, stream=True)
    if response.status_code != 200:
        print(f"failed generating static analysis report json : {response.content}")
        exit(1)
    with open(f"{APPNAME}_{HASH}_static.json", "wb") as f:
        f.write(response.content)
    print(f"Static json saved as {APPNAME}_{HASH}_static.json")


def start_dynamic_analysis():
    response = requests.post(SERVER + '/api/v1/dynamic/start_analysis', data=DATA_HASH, headers=API_KEY_HEADERS)
    if response.status_code != 200:
        print(f"failed to start analysis : {response.content}")
        exit(1)
    print(f"Successfully Start Dynamic Analysis")


def set_proxy():
    print("Set Proxy")
    _set = {'action': 'set'}
    response = requests.post(SERVER + '/api/v1/android/global_proxy', data=_set, headers=API_KEY_HEADERS)
    if response.status_code != 200:
        print(f"failed to set proxy : {response.content}")
        exit(1)
    print(f"Successfully Set Proxy")

def mobsfy():
    print("MobSFY android runtime environment")
    response = requests.post(SERVER + '/api/v1/android/mobsfy', data=ADB_IDENTIFIER,headers=API_KEY_HEADERS)
    if response.status_code != 200:
        print(f"failed to mobsfy : {response.content}")
        exit(1)
    print("Successfully MobSfy")

def test_activity(action):
    print(f"Start test {action} Activity")
    data = {"hash": HASH, "test": action}
    response = requests.post(SERVER + '/api/v1/android/activity', data=data, headers=API_KEY_HEADERS)
    if response.status_code != 200:
        print(f"failed to test activity : {response.content}")
        exit(1)
    print(f"Successfully tested {action} Activity")

def tls_test():
    print("Start TLS/SSL Test")
    response = requests.post(SERVER + '/api/v1/android/tls_tests', data=DATA_HASH, headers=API_KEY_HEADERS)
    if response.status_code != 200:
        print(f"failed to tls_test : {response.content}")
        exit(1)
    print("Successfully TLS/SSL Test")

def dynamic_json():
    print("Generate dynamic analysis report to JSON")
    response = requests.post(SERVER + '/api/v1/dynamic/report_json', data=DATA_HASH, headers=API_KEY_HEADERS)
    if response.status_code != 200:
        print(f"failed to generate dynamic analysis report json : {response.content}")
        exit(1)
    with open(f"{APPNAME}_{HASH}_dynamic.json", "wb") as f:
        f.write(response.content)
    print(f"Dynamic json saved as {APPNAME}_{HASH}_dynamic.json")


if __name__ == "__main__":
    fire.Fire(start)
