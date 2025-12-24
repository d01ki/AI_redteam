# AI_redteam

# Role
You are an expert Python developer specializing in LangChain and LangGraph.

# Task
I want to implement a multi-agent security assessment workflow based on the following architecture using **LangGraph**.
Please generate a modular Python project structure suitable for VS Code.

# Architecture Overview


```mermaid
graph TD
    %% スタイル定義
    classDef agent fill:#a6c1ff,stroke:#333,stroke-width:2px,color:black;
    classDef tool fill:#f4f9b8,stroke:#dcdcdc,stroke-width:1px,color:black,stroke-dasharray: 5 5;
    classDef startend fill:#ffffff,stroke:#333,stroke-width:2px,rx:10,ry:10;

    %% ノード定義
    Start((START / User)):::startend
    End((END / Report)):::startend

    %% LangGraphのエージェントノード
    subgraph Workflow [LangGraph Workflow]
        direction TB
        Op[Operator Agent]:::agent
        CVE[CVE Analyst Agent]:::agent
        PoC[PoC Search Agent]:::agent
        Exp[Exploit Agent]:::agent
        Rep[Report Agent]:::agent
    end

    %% ツール定義
    T_NVD[Search NVD]:::tool
    T_EDB[Search ExploitDB]:::tool
    T_MITRE[Search MITRE]:::tool
    
    T_EDB2[Search ExploitDB]:::tool
    T_GIT[Search Github]:::tool
    
    T_EXP1[Run exploit1.py]:::tool
    T_EXP2[Run exploit2.py]:::tool

    %% ワークフローの接続（実線）
    Start -->|Target IP| Op
    Op --> CVE
    CVE -->|CVE List| PoC
    PoC -->|PoC Info| Exp
    Exp -->|Exploit Result| Rep
    Rep -->|Final Report| End

    %% ツール利用の接続（点線）
    CVE -.-> T_NVD
    CVE -.-> T_EDB
    CVE -.-> T_MITRE
    
    PoC -.-> T_EDB2
    PoC -.-> T_GIT
    
    Exp -.-> T_EXP1
    Exp -.-> T_EXP2
```



1.  **Shared State (`AgentState`):**
    -   `target_ip` (str)
    -   `cve_list` (List[str])
    -   `poc_info` (List[str])
    -   `exploit_results` (str)
    -   `final_report` (str)
    -   `messages` (List[BaseMessage])

2.  **Agents (Nodes):**
    -   `Operator`: Entry point. Initializes the workflow with the target IP.
    -   `CVE Analyst`: Uses tools (mock) to search NVD/MITRE for the target IP and updates `cve_list`.
    -   `PoC Search`: Searches ExploitDB/Github (mock) for the found CVEs and updates `poc_info`.
    -   `Exploit Agent`: Executes exploit scripts (mock) based on PoC info and updates `exploit_results`.
    -   `Report Agent`: Aggregates all info into a final report string.

3.  **Workflow (Graph Edges):**
    Operator -> CVE Analyst -> PoC Search -> Exploit Agent -> Report Agent -> END

# Requirements
-   **File Structure:** Please propose a clean directory structure (e.g., `main.py`, `state.py`, `agents/`, `tools/`).
-   **LangGraph Implementation:** Use `StateGraph` to connect the nodes.
-   **Tools:** Create dummy/mock functions for the tools (e.g., `search_nvd`, `run_exploit`) using the `@tool` decorator.
-   **Environment:** Use `python-dotenv` to load API keys.
-   **Code:** Provide the full code for `main.py`, `state.py`, and examples for the agents and tools.

Please start by showing the file structure, then provide the code for each file.
