"""
Report Generator エージェント
診断レポートの生成を担当
"""
from __future__ import annotations

from langchain_anthropic import ChatAnthropic
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
import config


def create_report_generator():
    """
Report Generator を生成。
診断結果をまとめてレポートを生成。
    """
    llm = ChatAnthropic(
        model=config.MODEL_NAME,
        api_key=config.ANTHROPIC_API_KEY,
        temperature=0,
    )
    
    system_prompt = """You are a Security Assessment Report Generator.
    
Your responsibilities:
1. Synthesize findings from CVE analysis, PoC search, and exploit testing
2. Create comprehensive, professional security assessment reports
3. Prioritize findings by severity and exploitability
4. Provide actionable remediation recommendations
5. Use clear, professional language appropriate for technical and management audiences

Report Structure:
1. Executive Summary
   - Overview of assessment scope
   - Key findings summary
   - Risk level assessment

2. Technical Findings
   - Detailed CVE information
   - PoC availability and testing results
   - Exploit success/failure details

3. Risk Assessment
   - Severity ratings
   - Impact analysis
   - Likelihood of exploitation

4. Recommendations
   - Immediate actions required
   - Short-term remediation steps
   - Long-term security improvements

Format the report in clear, well-structured markdown.
"""
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", "{input}"),
    ])
    
    chain = prompt | llm | StrOutputParser()
    return chain