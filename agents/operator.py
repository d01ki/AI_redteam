from __future__ import annotations

from langchain_core.messages import AIMessage, HumanMessage

from state import AgentState


def operator_node(state: AgentState) -> AgentState:
    """
    Operator (Supervisor) エージェント
    全体の状態を見て次のアクションを決定する。
    """
    target = state.get("target_ip", "")
    messages = list(state.get("messages", []))
    phase_history = list(state.get("phase_history", []))
    
    cve_list = state.get("cve_list", [])
    poc_info = state.get("poc_info", [])
    exploit_success = state.get("exploit_success", False)
    exploit_attempts = state.get("exploit_attempts", 0)
    max_attempts = state.get("max_exploit_attempts", 5)
    cve_search_count = state.get("cve_search_count", 0)
    poc_search_count = state.get("poc_search_count", 0)
    
    # 初回起動
    if not phase_history:
        messages.append(HumanMessage(content=f"Target: {target}"))
        messages.append(AIMessage(content="Operator: 診断を開始します"))
        phase_history.append("start")
        next_action = "investigate_cve"
        messages.append(AIMessage(content="Operator: → CVE調査を実行"))
    
    # 既に成功している場合
    elif exploit_success:
        next_action = "generate_report"
        messages.append(AIMessage(content="Operator: Exploit成功 → レポート生成へ"))
    
    # CVEが見つかっていない場合
    elif not cve_list:
        if cve_search_count < 2:
            next_action = "investigate_cve"
            messages.append(AIMessage(content=f"Operator: CVE未発見 → 再調査 ({cve_search_count + 1}/2)"))
        else:
            next_action = "generate_report"
            messages.append(AIMessage(content="Operator: CVE発見できず → レポート生成"))
    
    # CVEはあるがPoCがない場合
    elif cve_list and not poc_info:
        if poc_search_count < 2:
            next_action = "search_poc"
            messages.append(AIMessage(content=f"Operator: PoC検索へ ({poc_search_count + 1}/2)"))
        else:
            next_action = "generate_report"
            messages.append(AIMessage(content="Operator: PoC発見できず → レポート生成"))
    
    # PoCがあるがExploit未試行または失敗中
    elif poc_info and not exploit_success:
        if exploit_attempts < max_attempts:
            next_action = "run_exploit"
            messages.append(AIMessage(content=f"Operator: Exploit実行へ ({exploit_attempts + 1}/{max_attempts})"))
        else:
            next_action = "generate_report"
            messages.append(AIMessage(content="Operator: 最大試行回数到達 → レポート生成"))
    
    # その他（レポート生成）
    else:
        next_action = "generate_report"
        messages.append(AIMessage(content="Operator: → レポート生成"))
    
    phase_history.append(next_action)
    
    return {
        **state,
        "next_action": next_action,
        "phase_history": phase_history,
        "messages": messages,
    }


def route_next_action(state: AgentState) -> str:
    """Operatorの決定に基づいてルーティング."""
    action = state.get("next_action", "generate_report")
    
    routing = {
        "investigate_cve": "cve_analyst",
        "retry_cve": "cve_analyst",
        "search_poc": "poc_search",
        "retry_poc": "poc_search",
        "run_exploit": "exploit",
        "generate_report": "report",
        "done": "end",
    }
    
    return routing.get(action, "report")
