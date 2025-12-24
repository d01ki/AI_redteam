"""
CVE Analyst エージェント
脆弱性情報の収集・分析を担当
"""
from __future__ import annotations

from langchain_anthropic import ChatAnthropic
from langchain.agents import create_react_agent
from langchain_core.prompts import ChatPromptTemplate
from tools.security_tools import search_nvd_cves, analyze_cve_severity
import config


def create_cve_analyst_agent():
    """
CVE Analyst エージェントを生成。
    NVD APIを使用してCVE情報を検索・分析。
    """
    llm = ChatAnthropic(
        model=config.MODEL_NAME,
        api_key=config.ANTHROPIC_API_KEY,
        temperature=0,
    )
    
    tools = [search_nvd_cves, analyze_cve_severity]
    
    system_prompt = """You are a CVE (Common Vulnerabilities and Exposures) Analyst.
    
Your responsibilities:
1. Search for CVE information related to the target using NVD API
2. Analyze the severity and impact of discovered vulnerabilities
3. Prioritize vulnerabilities based on CVSS scores and exploitability
4. Provide clear, actionable summaries of findings

Always use the available tools to gather accurate, up-to-date CVE information.
Focus on high-severity vulnerabilities that have known exploits.

When you finish your analysis, provide:
- List of relevant CVE IDs
- Brief description of each vulnerability
- Severity assessment
- Recommendation on which CVEs to investigate further
"""
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", "{input}"),
        ("placeholder", "{agent_scratchpad}"),
    ])
    
    agent = create_react_agent(llm, tools, prompt)
    return agent