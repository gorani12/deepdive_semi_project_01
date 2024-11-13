import os
import subprocess
from Cryptodome.Cipher import AES

# 도구 경로 설정 (자신의 환경에 맞게 수정)
# JAVA_HOME 환경변수가 설정되어있어야함
APKTOOL_PATH = ".\\apktool.bat"
KEYTOOL_PATH = os.environ['JAVA_HOME']+"\\bin\\keytool.exe"
JARSIGNER_PATH = os.environ['JAVA_HOME']+"\\bin\\jarsigner.exe"
ZIPALIGN_PATH = os.environ['LocalAppData']+"\\Android\\Sdk\\build-tools\\34.0.0\\zipalign.exe"

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
            try:
                aes.decrypt_file(dex_path, output_path)
                os.remove(dex_path)
                os.rename(output_path, dex_path)
            except Exception as e:
                print(f"{filename}는 복호화되지 않았습니다: {e}")

def decompile_apk(apk_path):
    try:
        subprocess.run([APKTOOL_PATH, "d", "-s", apk_path], check=True)
        print("APK 디컴파일 완료.")
    except subprocess.CalledProcessError as e:
        print(f"APK 디컴파일 실패: {e}")

def repackage_apk(decompiled_folder, output_apk_path):
    try:
        subprocess.run([APKTOOL_PATH, "b", decompiled_folder, "-o", output_apk_path], check=True)
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
            ], check=True)
            print("Keystore 생성 완료.")
        
        subprocess.run([
            JARSIGNER_PATH, "-verbose", "-keystore", keystore_path, "-storepass", password,
            "-signedjar", signed_apk_path, apk_path, alias
        ], check=True)
        print("APK 서명 완료.")
    except subprocess.CalledProcessError as e:
        print(f"APK 서명 실패: {e}")

def decrypt_and_repack(apk_path, key):
    apk_name = os.path.splitext(apk_path)[0]
    decompiled_folder = apk_name
    output_apk_path = "app.apk"
    signed_apk_path = "output.apk"

    decompile_apk(apk_path)
    decrypt_all_dex_files(decompiled_folder, key)
    repackage_apk(decompiled_folder, output_apk_path)
    sign_apk(output_apk_path, signed_apk_path)

if __name__ == "__main__":
    key = "dbcdcfghijklmaop"
    apk_path = "pgsHZz.apk"
    decrypt_and_repack(apk_path, key)
