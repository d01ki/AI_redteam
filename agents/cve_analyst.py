from __future__ import annotations

import re
from langchain_core.messages import AIMessage
from langgraph.prebuilt import ToolNode

from state import AgentState
from tools.security_tools import search_exploitdb, search_mitre, search_nvd

# ツールリスト
CVE_TOOLS = [search_nvd, search_mitre, search_exploitdb]


def extract_cve_ids(text: str) -> list[str]:
    """テキストからCVE-IDを抽出する."""
    pattern = r'CVE-\d{4}-\d{4,}'
    return list(set(re.findall(pattern, text, re.IGNORECASE)))


def cve_analyst_node(state: AgentState) -> AgentState:
    """
    CVE Analyst エージェント
    3つのソース（NVD, MITRE, ExploitDB）を統合検索する。
    検索後は Operator に戻る。
    """
    target = state.get("target_ip", "")
    messages = list(state.get("messages", []))
    existing_cves = list(state.get("cve_list", []))
    search_count = state.get("cve_search_count", 0)
    
    messages.append(AIMessage(content=f"CVE Analyst: {target} の脆弱性を検索中..."))
    
    found_cve_ids: list[str] = []
    
    # NVD 検索（ツール使用）
    try:
        nvd_result = search_nvd.invoke({"target": target})
        cve_ids = extract_cve_ids(nvd_result)
        found_cve_ids.extend(cve_ids)
        messages.append(AIMessage(content=f"  [Tool:NVD] {len(cve_ids)}件のCVE-ID発見"))
    except Exception as e:
        messages.append(AIMessage(content=f"  [Tool:NVD] エラー: {e}"))
    
    # MITRE 検索（ツール使用）- CVE-IDがある場合のみ詳細を取得
    if found_cve_ids:
        try:
            # 最初のCVEの詳細を取得
            mitre_result = search_mitre.invoke({"target": found_cve_ids[0]})
            messages.append(AIMessage(content=f"  [Tool:MITRE] {mitre_result}"))
        except Exception as e:
            messages.append(AIMessage(content=f"  [Tool:MITRE] エラー: {e}"))
    
    # 既存と統合して重複除去（CVE-ID形式のみ）
    all_cves = list(set(existing_cves + found_cve_ids))
    messages.append(AIMessage(content=f"CVE Analyst: 完了 - {len(all_cves)} 件のCVE → Operator へ報告"))

    return {
        **state,
        "cve_list": all_cves,
        "cve_search_count": search_count + 1,
        "messages": messages,
    }
