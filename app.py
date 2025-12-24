from __future__ import annotations

import os
import base64
from io import BytesIO
from typing import Any, Dict

from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify, Response
from langgraph.constants import END
from langgraph.graph import StateGraph

from agents.cve_analyst import cve_analyst_node
from agents.exploit import exploit_node
from agents.operator import operator_node, route_next_action
from agents.poc_search import poc_search_node
from agents.report import report_node
from state import AgentState

load_dotenv()

app = Flask(__name__)


def build_graph() -> Any:
    """
    Operator中心のマルチエージェント構成。
    全エージェントが Operator と繋がり、Operator が次のアクションを決定する。
    
    構成:
        ┌────────────────────────────────────┐
        │             Operator               │
        │  (状態を見て次のアクションを決定)    │
        └──────────┬─────────────────────────┘
                   │ (条件分岐)
        ┌──────────┼──────────┬──────────┐
        ▼          ▼          ▼          ▼
    CVE Analyst  PoC Search  Exploit   Report
        │          │          │          │
        └──────────┴──────────┴──────────┘
                   │
                   ▼
               Operator (ループ)
    """
    workflow = StateGraph(AgentState)

    # ノード登録
    workflow.add_node("operator", operator_node)
    workflow.add_node("cve_analyst", cve_analyst_node)
    workflow.add_node("poc_search", poc_search_node)
    workflow.add_node("exploit", exploit_node)
    workflow.add_node("report", report_node)

    # エントリーポイント: Operator
    workflow.set_entry_point("operator")

    # Operator → 条件分岐（次のアクションに応じてルーティング）
    workflow.add_conditional_edges(
        "operator",
        route_next_action,
        {
            "cve_analyst": "cve_analyst",
            "poc_search": "poc_search",
            "exploit": "exploit",
            "report": "report",
        }
    )
    
    # 各エージェント → Operator に戻る
    workflow.add_edge("cve_analyst", "operator")
    workflow.add_edge("poc_search", "operator")
    workflow.add_edge("exploit", "operator")
    
    # Report → END
    workflow.add_edge("report", END)

    return workflow.compile()


def get_mermaid_code(compiled_app: Any) -> str:
    """Mermaid形式でグラフを取得."""
    graph = compiled_app.get_graph()
    return graph.draw_mermaid()


def get_graph_png_bytes(compiled_app: Any) -> bytes:
    """PNG形式でグラフを取得 (draw_mermaid_png)."""
    graph = compiled_app.get_graph()
    return graph.draw_mermaid_png()


def run_workflow(target_ip: str, dry_run: bool = True) -> Dict[str, Any]:
    """ワークフローを実行."""
    initial_state: AgentState = {
        "target_ip": target_ip,
        "dry_run": dry_run,
        "next_action": "investigate_cve",
        "phase_history": [],
        "cve_list": [],
        "cve_search_count": 0,
        "poc_info": [],
        "poc_search_count": 0,
        "exploit_results": "",
        "exploit_success": False,
        "exploit_attempts": 0,
        "max_exploit_attempts": 5,
        "final_report": "",
        "messages": [],
    }

    compiled_app = build_graph()
    final_state = compiled_app.invoke(initial_state)
    return final_state


@app.route("/")
def index():
    """メインページ."""
    compiled_app = build_graph()
    mermaid_code = get_mermaid_code(compiled_app)
    return render_template("index.html", mermaid_code=mermaid_code)


@app.route("/api/run", methods=["POST"])
def api_run():
    """診断を実行するAPI."""
    data = request.get_json() or {}
    target_ip = data.get("target_ip", "192.0.2.10")
    dry_run = data.get("dry_run", True)

    result = run_workflow(target_ip, dry_run)

    return jsonify({
        "target_ip": result.get("target_ip"),
        "cve_list": result.get("cve_list", []),
        "poc_info": result.get("poc_info", []),
        "exploit_results": result.get("exploit_results", ""),
        "final_report": result.get("final_report", ""),
        "messages": [str(m.content) for m in result.get("messages", [])],
    })


@app.route("/api/graph")
def api_graph():
    """グラフ情報を取得するAPI."""
    compiled_app = build_graph()
    mermaid_code = get_mermaid_code(compiled_app)
    return jsonify({"mermaid": mermaid_code})


@app.route("/api/graph.png")
def api_graph_png():
    """PNG画像としてグラフを返す (draw_mermaid_png)."""
    compiled_app = build_graph()
    try:
        png_bytes = get_graph_png_bytes(compiled_app)
        return Response(png_bytes, mimetype="image/png")
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)
