from crewai import Crew

def run_research_crew(agents, tasks):
    crew = Crew(agents=agents, tasks=tasks)
    return crew.kickoff()
