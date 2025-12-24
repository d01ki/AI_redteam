from __future__ import annotations

from langchain_core.messages import AIMessage

from state import AgentState
from tools.security_tools import search_exploitdb, search_github

# ツールリスト
POC_TOOLS = [search_exploitdb, search_github]


def poc_search_node(state: AgentState) -> AgentState:
    """
    PoC Search エージェント
    発見されたCVEに対してExploitDBとGitHubでPoCを検索する。
    検索後は Operator に戻る。
    """
    messages = list(state.get("messages", []))
    existing_poc = list(state.get("poc_info", []))
    search_count = state.get("poc_search_count", 0)
    
    messages.append(AIMessage(content="PoC Search: PoC/Exploitコードを検索中..."))

    poc_info: list[str] = []
    for cve in state.get("cve_list", []):
        # ExploitDB検索（ツール使用）
        try:
            edb_result = search_exploitdb.invoke({"cve": cve})
            poc_info.append(edb_result)
            messages.append(AIMessage(content=f"  [Tool:ExploitDB] {edb_result}"))
        except Exception as e:
            messages.append(AIMessage(content=f"  [Tool:ExploitDB] エラー: {e}"))
        
        # GitHub検索（ツール使用）
        try:
            gh_result = search_github.invoke({"cve": cve})
            poc_info.append(gh_result)
            messages.append(AIMessage(content=f"  [Tool:GitHub] {gh_result}"))
        except Exception as e:
            messages.append(AIMessage(content=f"  [Tool:GitHub] エラー: {e}"))

    # 既存と統合して重複除去
    all_poc = list(set(existing_poc + [p for p in poc_info if p]))
    messages.append(AIMessage(content=f"PoC Search: 完了 - {len(all_poc)} 件 → Operator へ報告"))

    return {
        **state,
        "poc_info": all_poc,
        "poc_search_count": search_count + 1,
        "messages": messages,
    }
