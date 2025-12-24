"""セキュリティ診断用のツール群."""
from __future__ import annotations

import requests
import time
from typing import List, Dict, Any
from langchain.tools import tool
import config


@tool
def search_nvd_cves(target: str) -> str:
    """NVD APIを使用してCVE情報を検索します。
    
    Args:
        target: 検索対象のキーワード（例: 'log4j', 'apache', 'CVE-2021-44228'）
    
    Returns:
        検索結果のテキスト（CVE IDと概要のリスト）
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {}
    if config.NVD_API_KEY:
        headers["apiKey"] = config.NVD_API_KEY
    
    params = {
        "keywordSearch": target,
        "resultsPerPage": 10,
    }
    
    try:
        response = requests.get(url, params=params, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return f"CVE情報が見つかりませんでした: {target}"
        
        results = []
        for vuln in vulnerabilities[:5]:  # 上位5件
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "N/A")
            descriptions = cve_data.get("descriptions", [])
            description = descriptions[0].get("value", "説明なし") if descriptions else "説明なし"
            results.append(f"- {cve_id}: {description[:100]}...")
        
        return "\n".join(results)
    
    except Exception as e:
        return f"NVD API エラー: {str(e)}"


@tool
def search_github_pocs(cve_id: str) -> str:
    """GitHub APIを使用してPoCコードを検索します。
    
    Args:
        cve_id: CVE ID（例: 'CVE-2021-44228'）
    
    Returns:
        検索結果のテキスト（リポジトリ名、スター数、URL）
    """
    url = "https://api.github.com/search/repositories"
    headers = {}
    if config.GITHUB_TOKEN:
        headers["Authorization"] = f"token {config.GITHUB_TOKEN}"
    
    params = {
        "q": f"{cve_id} PoC OR exploit",
        "sort": "stars",
        "order": "desc",
        "per_page": 5,
    }
    
    try:
        response = requests.get(url, params=params, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        items = data.get("items", [])
        if not items:
            return f"PoCが見つかりませんでした: {cve_id}"
        
        results = []
        for repo in items:
            name = repo.get("full_name", "N/A")
            stars = repo.get("stargazers_count", 0)
            url = repo.get("html_url", "")
            description = repo.get("description", "説明なし")[:80]
            results.append(f"- {name} (★{stars}): {description}\n  {url}")
        
        return "\n\n".join(results)
    
    except Exception as e:
        return f"GitHub API エラー: {str(e)}"


@tool
def simulate_exploit_execution(target: str, poc_description: str, dry_run: bool = True) -> str:
    """エクスプロイトの実行をシミュレートします。
    
    Args:
        target: ターゲット（IP or ホスト名）
        poc_description: 使用するPoCの説明
        dry_run: Trueの場合、実際には実行せずシミュレーションのみ
    
    Returns:
        実行結果のテキスト
    """
    import random
    
    if dry_run:
        # シミュレーション（ランダムで成功/失敗）
        success = random.choice([True, False])
        if success:
            return f"[SUCCESS] {target} に対するエクスプロイトが成功しました（シミュレーション）\nPoC: {poc_description[:50]}..."
        else:
            return f"[FAILED] {target} に対するエクスプロイトが失敗しました（シミュレーション）\nPoC: {poc_description[:50]}..."
    else:
        # 実際の実行は安全上の理由から未実装
        return "[INFO] 実際のエクスプロイト実行は未実装です。dry_run=Trueでシミュレーションを実行してください。"


@tool  
def analyze_cve_severity(cve_id: str) -> str:
    """CVEの深刻度を分析します。
    
    Args:
        cve_id: CVE ID（例: 'CVE-2021-44228'）
    
    Returns:
        深刻度分析の結果
    """
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {}
    if config.NVD_API_KEY:
        headers["apiKey"] = config.NVD_API_KEY
    
    params = {"cveId": cve_id}
    
    try:
        response = requests.get(url, params=params, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return f"CVE {cve_id} の情報が見つかりませんでした"
        
        vuln = vulnerabilities[0]
        metrics = vuln.get("cve", {}).get("metrics", {})
        
        # CVSS v3.x
        cvss_v3 = metrics.get("cvssMetricV31", [{}])[0] if metrics.get("cvssMetricV31") else {}
        if not cvss_v3:
            cvss_v3 = metrics.get("cvssMetricV30", [{}])[0] if metrics.get("cvssMetricV30") else {}
        
        cvss_data = cvss_v3.get("cvssData", {})
        base_score = cvss_data.get("baseScore", "N/A")
        base_severity = cvss_data.get("baseSeverity", "N/A")
        vector = cvss_data.get("vectorString", "N/A")
        
        return f"CVE {cve_id}\n深刻度: {base_severity} (スコア: {base_score})\nベクター: {vector}"
    
    except Exception as e:
        return f"深刻度分析エラー: {str(e)}"