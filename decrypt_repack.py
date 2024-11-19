import os
import subprocess
from Cryptodome.Cipher import AES

# ============================================================================================
# 도구 경로 설정 (Windows) / JAVA_HOME 환경변수 설정할 것
APKTOOL_PATH = ".\\apktool.bat"
KEYTOOL_PATH = os.environ['JAVA_HOME']+"\\bin\\keytool.exe"
JARSIGNER_PATH = os.environ['JAVA_HOME']+"\\bin\\jarsigner.exe"
ZIPALIGN_PATH = os.environ['LocalAppData']+"\\Android\\Sdk\\build-tools\\34.0.0\\zipalign.exe"
# ============================================================================================
# 도구 경로 설정 (MacOS)
# APKTOOL_PATH = 
# KEYTOOL_PATH = 
# JARSIGNER_PATH = 
# ZIPALIGN_PATH = 
# ============================================================================================

class AESCipherECB:
    def __init__(self, key):
        self.key = key.encode('utf-8')

    def decrypt_file(self, encrypted_file_path, output_file_path):
        with open(encrypted_file_path, "rb") as f:
            encrypted_data = f.read()

        cipher = AES.new(self.key, AES.MODE_ECB)
        decrypted_data = self.unpad(cipher.decrypt(encrypted_data))

        with open(output_file_path, "wb") as f:
            f.write(decrypted_data)
        print(f"복호화 완료: '{encrypted_file_path}' → '{output_file_path}'")

    def unpad(self, s):
        return s[:-s[-1]]

def decrypt_all_dex_files(directory, key):
    aes = AESCipherECB(key)
    for filename in os.listdir(directory):
        if filename.endswith(".dex"):
            dex_path = os.path.join(directory, filename)
            output_path = os.path.join(directory, f"decrypted_{filename}")

            # 로그: 암호화된 DEX 파일 탐색
            print(f"[INFO] DEX 파일 발견: {filename}")
            print(f"[INFO] 복호화 키: {key}")

            try:
                # 로그: 복호화 시작
                print(f"[INFO] {filename} 복호화 중...")
                aes.decrypt_file(dex_path, output_path)
                
                # 원본 파일 교체
                os.remove(dex_path)
                os.rename(output_path, dex_path)
                
                # 로그: 복호화 완료
                print(f"[SUCCESS] {filename} 복호화 완료.")

            except Exception as e:
                # 로그: 복호화 실패
                print(f"[ERROR] {e}")
                print(f"[ERROR] {filename} 복호화 실패: 해당 파일은 암호화되지 않음.")

def decompile_apk(apk_path):
    try:
        subprocess.run([APKTOOL_PATH, "d", "-s", apk_path], stdin=subprocess.DEVNULL, check=True)
        print("APK 디컴파일 완료.")
    except subprocess.CalledProcessError as e:
        print(f"APK 디컴파일 실패: {e}")

def repackage_apk(decompiled_folder, output_apk_path):
    try:
        subprocess.run([APKTOOL_PATH, "b", decompiled_folder, "-o", output_apk_path], stdin=subprocess.DEVNULL, check=True)
        print("APK 리패키징 완료.")
    except subprocess.CalledProcessError as e:
        print(f"APK 리패키징 실패: {e}")

def sign_apk(apk_path, signed_apk_path, keystore_path="dev.key", alias="dev", password="123456"):
    try:
        if not os.path.exists(keystore_path):
            subprocess.run([
                KEYTOOL_PATH, "-genkey", "-v", "-keystore", keystore_path, "-alias", alias,
                "-keyalg", "RSA", "-keysize", "2048", "-dname", "CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown",
                "-storepass", password, "-keypass", password
            ], stdin=subprocess.DEVNULL, check=True)
            print("Keystore 생성 완료.")
        
        subprocess.run([
            JARSIGNER_PATH, "-verbose", "-keystore", keystore_path, "-storepass", password,
            "-signedjar", signed_apk_path, apk_path, alias
        ], stdin=subprocess.DEVNULL, check=True)
        print("APK 서명 완료.")
    except subprocess.CalledProcessError as e:
        print(f"APK 서명 실패: {e}")

def decrypt_and_repack(apk_path, key):
    apk_name = os.path.splitext(apk_path)[0]
    decompiled_folder = apk_name
    output_apk_path = "app.apk"
    signed_apk_path = "decrypt_"+apk_path.split("\\")[-1]

    decompile_apk(apk_path)
    decrypt_all_dex_files(decompiled_folder, key)
    repackage_apk(decompiled_folder, output_apk_path)
    sign_apk(output_apk_path, signed_apk_path)
    return signed_apk_path

if __name__ == "__main__":
    key = "dbcdcfghijklmaop"
    apk_path = "sample.apk"
    decrypt_and_repack(apk_path, key)
