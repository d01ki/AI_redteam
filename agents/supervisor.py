"""
Supervisor エージェント
マルチエージェントワークフローの調整を担当
"""
from __future__ import annotations

from langchain_anthropic import ChatAnthropic
from langchain.agents import AgentExecutor, create_react_agent
from langchain_core.prompts import ChatPromptTemplate
from langchain.tools import tool
import config

# 各サブエージェントのインポート
from agents.cve_analyst import create_cve_analyst_agent
from agents.poc_search import create_poc_search_agent
from agents.exploit import create_exploit_agent
from agents.report import create_report_generator


# サブエージェントをツールとしてラップ（グローバルインスタンス）
cve_analyst_agent = None
poc_search_agent = None
exploit_agent = None
report_generator = None


def initialize_agents():
    """All sub-agentsを初期化."""
    global cve_analyst_agent, poc_search_agent, exploit_agent, report_generator
    
    if cve_analyst_agent is None:
        cve_analyst_agent = AgentExecutor(
            agent=create_cve_analyst_agent(),
            tools=[],
            verbose=True,
            handle_parsing_errors=True,
        )
    
    if poc_search_agent is None:
        poc_search_agent = AgentExecutor(
            agent=create_poc_search_agent(),
            tools=[],
            verbose=True,
            handle_parsing_errors=True,
        )
    
    if exploit_agent is None:
        exploit_agent = AgentExecutor(
            agent=create_exploit_agent(),
            tools=[],
            verbose=True,
            handle_parsing_errors=True,
        )
    
    if report_generator is None:
        report_generator = create_report_generator()


@tool
def investigate_cve(target: str) -> str:
    """ターゲットにCVE調査を実施します。
    
    Args:
        target: 調査対象（ソフトウェア名、ホスト名、CVE-IDなど）
    
    Returns:
        CVE調査の結果（発見されたCVE IDと深刻度評価）
    """
    initialize_agents()
    
    input_text = f"""
Perform CVE investigation for target: {target}

Steps:
1. Search for CVEs related to this target using search_nvd_cves
2. Analyze severity of discovered CVEs using analyze_cve_severity
3. Prioritize CVEs by CVSS score and exploitability
4. Provide summary of findings with CVE IDs

Target: {target}
"""
    
    try:
        result = cve_analyst_agent.invoke({"input": input_text})
        return result.get("output", str(result))
    except Exception as e:
        return f"CVE investigation error: {str(e)}"


@tool
def search_poc(cve_ids: str) -> str:
    """CVE IDに対するPoCコードを検索します。
    
    Args:
        cve_ids: カンマ区切りのCVE IDリスト（例: "CVE-2021-44228, CVE-2021-45046"）
    
    Returns:
        発見されたPoCリポジトリの情報
    """
    initialize_agents()
    
    input_text = f"""
Search for PoC code for the following CVE IDs: {cve_ids}

Steps:
1. For each CVE ID, use search_github_pocs to find PoC repositories
2. Evaluate repository quality (stars, updates, documentation)
3. Identify the most reliable PoCs
4. Provide summary with links and recommendations

CVE IDs: {cve_ids}
"""
    
    try:
        result = poc_search_agent.invoke({"input": input_text})
        return result.get("output", str(result))
    except Exception as e:
        return f"PoC search error: {str(e)}"


@tool
def execute_exploit(target: str, poc_description: str, dry_run: bool = True) -> str:
    """エクスプロイトを実行（またはシミュレート）します。
    
    Args:
        target: ターゲット（IP or ホスト名）
        poc_description: 使用するPoCの説明
        dry_run: Trueの場合、シミュレーションのみ
    
    Returns:
        エクスプロイト実行結果
    """
    initialize_agents()
    
    input_text = f"""
Execute exploit against target: {target}

PoC Description: {poc_description}
Dry Run Mode: {dry_run}

Steps:
1. Use simulate_exploit_execution to test the PoC
2. Monitor execution results
3. Analyze success/failure
4. Provide detailed report of what happened

Target: {target}
Dry Run: {dry_run}
"""
    
    try:
        result = exploit_agent.invoke({"input": input_text})
        return result.get("output", str(result))
    except Exception as e:
        return f"Exploit execution error: {str(e)}"


@tool
def generate_report(findings_summary: str) -> str:
    """診断結果をまとめたレポートを生成します。
    
    Args:
        findings_summary: これまでの調査結果の要約
    
    Returns:
        完成したセキュリティ評価レポート
    """
    initialize_agents()
    
    input_text = f"""
Generate a comprehensive security assessment report based on these findings:

{findings_summary}

Include:
1. Executive Summary
2. Technical Findings (CVEs, PoCs, Exploit results)
3. Risk Assessment
4. Remediation Recommendations

Format as professional markdown report.
"""
    
    try:
        result = report_generator.invoke({"input": input_text})
        return result
    except Exception as e:
        return f"Report generation error: {str(e)}"


def create_supervisor_agent():
    """
Supervisor エージェントを生成。
全体のワークフローを調整。
    """
    llm = ChatAnthropic(
        model=config.MODEL_NAME,
        api_key=config.ANTHROPIC_API_KEY,
        temperature=0,
    )
    
    tools = [
        investigate_cve,
        search_poc,
        execute_exploit,
        generate_report,
    ]
    
    system_prompt = """You are a Security Assessment Supervisor.
    
Your role is to orchestrate a comprehensive security assessment workflow by coordinating specialized agents:

1. CVE Analyst - Investigates vulnerabilities
2. PoC Search - Finds proof-of-concept exploit code
3. Exploit Tester - Tests exploits (simulation)
4. Report Generator - Creates final assessment report

WORKFLOW:
1. Start with CVE investigation for the target
2. If CVEs are found, search for PoCs
3. If PoCs are found, attempt exploitation (simulation)
4. Generate comprehensive report with all findings

DECISION MAKING:
- If no CVEs found after investigation, proceed to report
- If CVEs found but no PoCs, document this in report
- If exploit fails, you may retry up to 3 times with different approaches
- Always generate a final report regardless of findings

USE TOOLS SEQUENTIALLY:
1. investigate_cve(target) - First step
2. search_poc(cve_ids) - If CVEs found
3. execute_exploit(target, poc_description, dry_run) - If PoCs found
4. generate_report(findings_summary) - Final step

Provide clear status updates and reasoning for each decision.
"""
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", "{input}"),
        ("placeholder", "{agent_scratchpad}"),
    ])
    
    agent = create_react_agent(llm, tools, prompt)
    
    return AgentExecutor(
        agent=agent,
        tools=tools,
        verbose=True,
        handle_parsing_errors=True,
        max_iterations=15,
    )