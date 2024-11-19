import json
import requests
from datetime import datetime
import os


VT_API_URL = "https://www.virustotal.com/api/v3/domains/"

def load_json(file_path):
    """JSON 파일에서 데이터를 로드"""
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data

def get_virustotal_report(domain, api_key):
    """VirusTotal에서 도메인 평판 조회 및 추가 정보 가져오기"""
    headers = {"x-apikey": api_key}
    response = requests.get(VT_API_URL + domain, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})
        return attributes
    else:
        print(f"Error fetching data for {domain}. Status Code: {response.status_code}")
    return None


def analyze_domains(json_data, api_key):
    """JSON 파일에서 도메인 추출 후 VirusTotal 분석"""
    results = []
    domains = json_data.get("domains", {})
    
    for domain in domains:
        print(f"\nAnalyzing domain: {domain}")
        report = get_virustotal_report(domain, api_key)
        if report:
            results.append({ "domain": domain, "report": report })
    
    return results

def format_timestamp(timestamp):
    """Unix 타임스탬프를 읽기 쉬운 형식으로 변환"""
    if timestamp:
        return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
    return "N/A"

def print_report(analysis_results, output_path):
    """VirusTotal 도메인 분석 결과를 파일에 출력"""
    with open(output_path, "w") as txt_file:
        txt_file.write("\n[Detailed Analysis Results]\n")
        for result in analysis_results:
            domain = result["domain"]
            report = result["report"]
            
            txt_file.write(f"\nDomain: {domain}\n")
            txt_file.write(f"  - 평판 점수(0 기준 높을수록 신뢰도 높음): {report.get('reputation', 'N/A')}\n")
            
            # 분석 통계
            last_analysis_stats = report.get("last_analysis_stats", {})
            txt_file.write(f"  - 안전 보고서 수: {last_analysis_stats.get('harmless', 0)}\n")
            txt_file.write(f"  - 악성 보고서 수: {last_analysis_stats.get('malicious', 0)}\n")
            txt_file.write(f"  - 의심 보고서 수: {last_analysis_stats.get('suspicious', 0)}\n")
            txt_file.write(f"  - 탐지되지 않은 보고서 수: {last_analysis_stats.get('undetected', 0)}\n")
            
            # SSL 인증서 정보
            ssl_info = report.get("last_https_certificate", {})
            txt_file.write(f"  - SSL Issuer: {ssl_info.get('issuer', {}).get('name', 'N/A')}\n")
            txt_file.write(f"  - SSL Valid From: {ssl_info.get('validity', {}).get('not_before', 'N/A')}\n")
            txt_file.write(f"  - SSL Valid Until: {ssl_info.get('validity', {}).get('not_after', 'N/A')}\n")
            
            # IP 주소 및 연결 날짜
            resolutions = report.get("resolutions", [])
            if resolutions:
                txt_file.write("  - 연결된 IP 주소:\n")
                for res in resolutions:
                    ip_address = res.get("ip_address", "N/A")
                    last_resolved = format_timestamp(res.get("last_resolved"))
                    txt_file.write(f"    - {ip_address} (Last Resolved: {last_resolved})\n")
            
            # 악성 파일 해시
            downloaded_files = report.get("downloaded_files", [])
            if downloaded_files:
                txt_file.write("  - 악성 파일 해시:\n")
                for file in downloaded_files:
                    txt_file.write(f"    - {file['sha256']}\n")
            
            # WHOIS 정보 출력
            txt_file.write(f"  - Registrar: {report.get('registrar', 'Unknown')}\n")
            txt_file.write(f"  - Creation Date: {format_timestamp(report.get('creation_date'))}\n")
            txt_file.write(f"  - Last Modified: {format_timestamp(report.get('last_modification_date'))}\n")
            
            txt_file.write("-" * 50 + "\n")
    
    print(f"분석 파일 저장 위치 : '{output_path}'")


def make_virus_total_report():
    # CMD 인자 처리
    json_path = input("JSON 파일 경로를 입력하세요 : ").strip('"')
    api_key = input("VirusTotal의 API Key를 입력하세요 : ")

    json_data = load_json(json_path)
    analysis_results = analyze_domains(json_data, api_key)
    
    output_dir = os.path.dirname(json_path)
    
    # Output 디렉토리가 존재하지 않으면 생성
    try:
        os.makedirs(output_dir, exist_ok=True)
    except Exception as e:
        print(f"디렉토리를 생성하는 중 오류가 발생했습니다: {e}")
        return
    
    output_path = os.path.join(output_dir, "virus_total_report.txt")

    print_report(analysis_results, output_path)


if __name__ == "__main__":
    make_virus_total_report()
