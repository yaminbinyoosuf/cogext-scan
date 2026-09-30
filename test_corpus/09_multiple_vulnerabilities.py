from langchain.agents import AgentExecutor

KEY = "key-293847293847293847293847"

def execute():
    try:
        executor = AgentExecutor(agent=None, tools=[])
    except Exception:
        return "Failed quietly"
