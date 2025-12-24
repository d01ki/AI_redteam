"""
PoC Search エージェント
PoC/Exploitコードの検索を担当
"""
from __future__ import annotations

from langchain_anthropic import ChatAnthropic
from langchain.agents import create_react_agent
from langchain_core.prompts import ChatPromptTemplate
from tools.security_tools import search_github_pocs
import config


def create_poc_search_agent():
    """
PoC Search エージェントを生成。
GitHub APIを使用してPoCコードを検索。
    """
    llm = ChatAnthropic(
        model=config.MODEL_NAME,
        api_key=config.ANTHROPIC_API_KEY,
        temperature=0,
    )
    
    tools = [search_github_pocs]
    
    system_prompt = """You are a PoC (Proof of Concept) Search Specialist.
    
Your responsibilities:
1. Search for publicly available PoC and exploit code for given CVE IDs
2. Evaluate the quality and reliability of found PoCs based on:
   - Repository stars and activity
   - Code quality and documentation
   - Recent updates
   - Community feedback
3. Identify the most promising PoCs for testing
4. Summarize findings with links to repositories

Always use the search_github_pocs tool to find relevant repositories.
Prioritize well-maintained, popular repositories with clear documentation.

When you finish your search, provide:
- List of found PoC repositories
- Star counts and last update dates
- Brief assessment of each PoC's reliability
- Recommendation on which PoCs to test first
"""
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", "{input}"),
        ("placeholder", "{agent_scratchpad}"),
    ])
    
    agent = create_react_agent(llm, tools, prompt)
    return agent