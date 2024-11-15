import json
import requests
import argparse
from datetime import datetime

VT_API_URL = "https://www.virustotal.com/api/v3/domains/"

def load_json(file_path):
    """JSON 파일에서 데이터를 로드"""
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data

def get_virustotal_report(domain, api_key):
    """VirusTotal에서 도메인 평판 조회"""
    headers = {"x-apikey": api_key}
    response = requests.get(VT_API_URL + domain, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})
        return attributes
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

def print_report(analysis_results):
    """분석 결과 출력"""
    print("\n[Detailed Analysis Results]")
    for result in analysis_results:
        domain = result["domain"]
        report = result["report"]

        print(f"\nDomain: {domain}")
        print(f"  - Reputation Score: {report.get('reputation', 'N/A')}")
        
        # last_analysis_stats
        last_analysis_stats = report.get("last_analysis_stats", {})
        print(f"  - Harmless Reports: {last_analysis_stats.get('harmless', 0)}")
        print(f"  - Malicious Reports: {last_analysis_stats.get('malicious', 0)}")
        print(f"  - Suspicious Reports: {last_analysis_stats.get('suspicious', 0)}")
        print(f"  - Undetected Reports: {last_analysis_stats.get('undetected', 0)}")
        print(f"  - Timeout Reports: {last_analysis_stats.get('timeout', 0)}")
        
        # Categories
        categories = report.get("categories", {})
        if categories:
            print(f"  - Categories: {', '.join([f'{k}: {v}' for k, v in categories.items()])}")
        
        # Tags
        tags = report.get("tags", [])
        print(f"  - Tags: {', '.join(tags) if tags else 'None'}")
        
        # Creation and last modification date
        creation_date = format_timestamp(report.get("creation_date"))
        last_modification_date = format_timestamp(report.get("last_modification_date"))
        print(f"  - Creation Date: {creation_date}")
        print(f"  - Last Modified: {last_modification_date}")
        print("-" * 50)

def main():
    # argparse를 사용하여 Command Line 인자 처리
    parser = argparse.ArgumentParser(description="VirusTotal Domain Reputation Checker")
    parser.add_argument("api_key", help="VirusTotal API key")
    parser.add_argument("json_file", help="Path to input JSON file")
    args = parser.parse_args()
    
    # JSON 데이터 로드
    json_data = load_json(args.json_file)
    
    # 도메인 분석 수행
    analysis_results = analyze_domains(json_data, args.api_key)
    
    # 결과 출력
    print_report(analysis_results)

if __name__ == "__main__":
    main()
