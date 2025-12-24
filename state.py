from __future__ import annotations

from typing import List, Literal, TypedDict

from langchain_core.messages import BaseMessage


# Operatorが決定する次のアクション
NextAction = Literal[
    "investigate_cve",
    "search_poc", 
    "run_exploit",
    "generate_report",
    "retry_cve",
    "retry_poc",
    "done"
]


class AgentState(TypedDict, total=False):
    """Shared state flowing through the LangGraph workflow."""

    # 入力
    target_ip: str
    dry_run: bool
    
    # Operator制御
    next_action: NextAction
    phase_history: List[str]
    
    # CVE分析結果
    cve_list: List[str]
    cve_search_count: int
    
    # PoC検索結果
    poc_info: List[str]
    poc_search_count: int
    
    # Exploit結果
    exploit_results: str
    exploit_success: bool
    exploit_attempts: int
    max_exploit_attempts: int
    
    # 最終レポート
    final_report: str
    
    # メッセージ履歴
    messages: List[BaseMessage]
