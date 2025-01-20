from app.core.logging import configure_logging
from app.langgraph_workflow.langgraph_workflow_module import graph
logger = configure_logging()

def agent_service_simulation(query: str) -> str:
    """
    Simulate an agent service response for a user query.
    """
    try:
        logger.info(f"Processing query with LangGraph: {query}")
        
        # Process the query through LangGraph
        response = graph.process_message(query)
        
        # If no response is generated
        if not response:
            raise ValueError("Empty response received from LangGraph")
        
        return response
    except Exception as e:
        logger.error(f"Error processing query with LangGraph: {e}")
        return "Sorry, there was an issue processing your query."