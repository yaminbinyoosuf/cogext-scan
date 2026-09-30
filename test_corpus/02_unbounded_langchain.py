from langchain.agents import AgentExecutor, create_openai_tools_agent

def setup_agent(llm, tools, prompt):
    agent = create_openai_tools_agent(llm, tools, prompt)
    return AgentExecutor(agent=agent, tools=tools)
