import os
from langchain.agents import AgentExecutor

def build_clean_agent(agent, tools):
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("API key missing")

    return AgentExecutor(
        agent=agent,
        tools=tools,
        max_iterations=5,
        max_execution_time=60.0
    )
