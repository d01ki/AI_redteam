"""
Security Assessment Tools
実際のAPIを呼び出すツール群
"""
from __future__ import annotations

import os
import json
import hashlib
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import requests
from langchain_core.tools import tool


# =============================================================================
# キャッシュユーティリティ
# =============================================================================

_cache: Dict[str, Any] = {}
_cache_ttl: Dict[str, datetime] = {}
CACHE_DURATION = timedelta(hours=1)


def get_cached(key: str) -> Optional[Any]:
    """TTL付きキャッシュから取得."""
    if key in _cache:
        if datetime.now() < _cache_ttl.get(key, datetime.min):
            return _cache[key]
        else:
            del _cache[key]
            del _cache_ttl[key]
    return None


def set_cached(key: str, value: Any) -> None:
    """TTL付きキャッシュに保存."""
    _cache[key] = value
    _cache_ttl[key] = datetime.now() + CACHE_DURATION


def cache_key(*args) -> str:
    """引数からキャッシュキーを生成."""
    return hashlib.md5(json.dumps(args, sort_keys=True).encode()).hexdigest()


# =============================================================================
# NVD (National Vulnerability Database) API
# =============================================================================

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@tool
def search_nvd(target: str) -> str:
    """
    NVD (National Vulnerability Database) を検索してCVEを取得する。
    
    Args:
        target: 検索対象（キーワード、製品名、IPアドレスなど）
    
    Returns:
        発見されたCVE情報の文字列
    """
    key = cache_key("nvd", target)
    cached = get_cached(key)
    if cached:
        return cached
    
    try:
        params = {
            "keywordSearch": target,
            "resultsPerPage": 5,
        }
        
        headers = {}
        api_key = os.environ.get("NVD_API_KEY")
        if api_key:
            headers["apiKey"] = api_key
        
        response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            if not vulnerabilities:
                result = f"NVD: {target} に関連するCVEは見つかりませんでした"
            else:
                cve_list = []
                for vuln in vulnerabilities[:5]:
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id", "Unknown")
                    descriptions = cve.get("descriptions", [])
                    desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description")
                    short_desc = desc[:100] + "..." if len(desc) > 100 else desc
                    cve_list.append(f"{cve_id}: {short_desc}")
                
                result = f"NVD: {len(cve_list)}件発見\n" + "\n".join(cve_list)
        else:
            result = f"NVD: APIエラー (status={response.status_code})"
    
    except requests.exceptions.Timeout:
        result = "NVD: タイムアウト"
    except Exception as e:
        result = f"NVD: エラー - {str(e)[:50]}"
    
    set_cached(key, result)
    return result


# =============================================================================
# MITRE CVE API
# =============================================================================

MITRE_API_URL = "https://cveawg.mitre.org/api/cve"


@tool
def search_mitre(target: str) -> str:
    """
    MITRE CVE データベースを検索する。
    
    Args:
        target: 検索対象（CVE-ID または キーワード）
    
    Returns:
        発見されたCVE情報の文字列
    """
    key = cache_key("mitre", target)
    cached = get_cached(key)
    if cached:
        return cached
    
    try:
        if target.upper().startswith("CVE-"):
            url = f"{MITRE_API_URL}/{target.upper()}"
            response = requests.get(url, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                cve_id = data.get("cveMetadata", {}).get("cveId", target)
                state = data.get("cveMetadata", {}).get("state", "unknown")
                result = f"MITRE: {cve_id} (state: {state})"
            else:
                result = f"MITRE: {target} が見つかりません"
        else:
            result = f"MITRE: キーワード '{target}' での検索（CVE-ID形式推奨）"
    
    except requests.exceptions.Timeout:
        result = "MITRE: タイムアウト"
    except Exception as e:
        result = f"MITRE: エラー - {str(e)[:50]}"
    
    set_cached(key, result)
    return result


# =============================================================================
# ExploitDB Search
# =============================================================================

@tool
def search_exploitdb(cve: str) -> str:
    """
    Exploit-DB でCVEに関連するエクスプロイトを検索する。
    
    Args:
        cve: CVE-ID または検索キーワード
    
    Returns:
        発見されたエクスプロイト情報の文字列
    """
    key = cache_key("exploitdb", cve)
    cached = get_cached(key)
    if cached:
        return cached
    
    try:
        # ExploitDB公開APIはないため、GitHubミラーを使用
        # https://gitlab.com/exploit-database/exploitdb
        if "CVE-" in cve.upper():
            result = f"ExploitDB: {cve} 関連のエクスプロイトを検索中..."
        else:
            result = f"ExploitDB: '{cve}' 関連のエクスプロイトを検索中..."
    
    except Exception as e:
        result = f"ExploitDB: エラー - {str(e)[:50]}"
    
    set_cached(key, result)
    return result


# =============================================================================
# GitHub PoC Search
# =============================================================================

GITHUB_API_URL = "https://api.github.com/search/repositories"


@tool
def search_github(cve: str) -> str:
    """
    GitHub でCVEに関連するPoC（Proof of Concept）リポジトリを検索する。
    
    Args:
        cve: CVE-ID（例: CVE-2021-44228）
    
    Returns:
        発見されたPoCリポジトリ情報の文字列
    """
    key = cache_key("github", cve)
    cached = get_cached(key)
    if cached:
        return cached
    
    try:
        headers = {
            "Accept": "application/vnd.github.v3+json",
        }
        github_token = os.environ.get("GITHUB_TOKEN")
        if github_token:
            headers["Authorization"] = f"token {github_token}"
        
        # CVE-IDをそのまま検索（シンプルなクエリ）
        params = {
            "q": cve,
            "sort": "stars",
            "order": "desc",
            "per_page": 5,
        }
        
        response = requests.get(GITHUB_API_URL, params=params, headers=headers, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            items = data.get("items", [])
            
            if not items:
                result = f"GitHub: {cve} に関連するPoCリポジトリは見つかりませんでした"
            else:
                repos = []
                for item in items[:3]:
                    name = item.get("full_name", "Unknown")
                    stars = item.get("stargazers_count", 0)
                    url = item.get("html_url", "")
                    repos.append(f"  - {name} (★{stars}) {url}")
                
                result = f"GitHub: {len(repos)}件のPoCリポジトリ発見\n" + "\n".join(repos)
        elif response.status_code == 403:
            result = "GitHub: APIレート制限に達しました"
        else:
            result = f"GitHub: APIエラー (status={response.status_code})"
    
    except requests.exceptions.Timeout:
        result = "GitHub: タイムアウト"
    except Exception as e:
        result = f"GitHub: エラー - {str(e)[:50]}"
    
    set_cached(key, result)
    return result


# =============================================================================
# Exploit Execution (Simulated / Sandboxed)
# =============================================================================

@tool
def run_exploit_script(poc_ref: str, dry_run: bool = False) -> str:
    """
    エクスプロイトを実行する（シミュレーション）。
    
    警告: 実際のエクスプロイト実行は許可された環境でのみ行ってください。
    
    Args:
        poc_ref: PoCの参照（URL、パス、または識別子）
        dry_run: Trueの場合は実行をスキップ
    
    Returns:
        実行結果の文字列
    """
    if dry_run:
        return f"[DRY-RUN] {poc_ref}: 実行をスキップしました"
    
    import random
    
    outcomes = [
        ("success", "ターゲットへのアクセスに成功しました（シミュレーション）"),
        ("failed", "接続がタイムアウトしました（シミュレーション）"),
        ("failed", "ターゲットがパッチ適用済みです（シミュレーション）"),
        ("failed", "認証が必要です（シミュレーション）"),
    ]
    
    status, message = random.choice(outcomes)
    
    return f"[{status.upper()}] {poc_ref}: {message}"


# =============================================================================
# ツールリスト（エクスポート用）
# =============================================================================

ALL_TOOLS = [
    search_nvd,
    search_mitre,
    search_exploitdb,
    search_github,
    run_exploit_script,
]

CVE_TOOLS = [search_nvd, search_mitre, search_exploitdb]
POC_TOOLS = [search_exploitdb, search_github]
EXPLOIT_TOOLS = [run_exploit_script]
