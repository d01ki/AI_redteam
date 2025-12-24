from __future__ import annotations

from langchain_core.messages import AIMessage

from state import AgentState


def report_node(state: AgentState) -> AgentState:
    """
    Report エージェント
    全ての結果を集約して最終レポートを生成する。
    """
    target = state.get("target_ip", "unknown target")
    cves = state.get("cve_list", [])
    poc_info = state.get("poc_info", [])
    exploit_results = state.get("exploit_results", "")
    exploit_success = state.get("exploit_success", False)
    exploit_attempts = state.get("exploit_attempts", 0)
    phase_history = state.get("phase_history", [])

    status_text = "成功" if exploit_success else "失敗"
    
    summary_lines = [
        f"═══════════════════════════════════════",
        f"  Security Assessment Report",
        f"═══════════════════════════════════════",
        f"",
        f"Target: {target}",
        f"",
        f"[ワークフロー履歴]",
        f"  {' → '.join(phase_history)}",
        f"",
        f"[CVE Analysis]",
        f"  発見された候補: {len(cves)} 件",
        *[f"    • {cve}" for cve in cves],
        f"",
        f"[PoC Search]",
        f"  発見された PoC: {len(poc_info)} 件",
        *[f"    • {poc}" for poc in poc_info],
        f"",
        f"[Exploit Execution]",
        f"  試行回数: {exploit_attempts}",
        f"  結果: {status_text}",
        f"",
        f"[詳細ログ]",
        exploit_results or "  No exploits attempted.",
        f"",
        f"═══════════════════════════════════════",
    ]

    final_report = "\n".join(summary_lines)

    messages = list(state.get("messages", []))
    messages.append(AIMessage(content=f"Report: 診断完了 - Exploit {status_text}（{exploit_attempts}回試行）"))

    return {
        **state,
        "next_action": "done",
        "final_report": final_report,
        "messages": messages,
    }
