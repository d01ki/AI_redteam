from __future__ import annotations

from typing import TypedDict, List, Annotated
import operator
from langchain_core.messages import BaseMessage


class AgentState(TypedDict):
    """マルチエージェント診断ワークフローの状態."""
    
    # 基本設定
    target_ip: str
    dry_run: bool
    
    # ワークフロー制御
    next_action: str
    phase_history: List[str]
    
    # CVE情報
    cve_list: List[str]
    cve_search_count: int
    cve_details: str  # CVE詳細情報（テキスト）
    
    # PoC情報
    poc_info: List[str]
    poc_search_count: int
    
    # Exploit情報
    exploit_results: str
    exploit_success: bool
    exploit_attempts: int
    max_exploit_attempts: int
    
    # レポート
    final_report: str
    
    # メッセージ（LangChainのadd_messagesと互換）
    messages: Annotated[List[BaseMessage], operator.add]