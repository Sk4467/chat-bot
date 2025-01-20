from langgraph.graph import MessagesState, StateGraph, START, END
from langchain_aws import ChatBedrock
from langchain_core.prompts import ChatPromptTemplate
from langchain_aws import ChatBedrockConverse
from langchain.prompts import PromptTemplate
import boto3
from typing import Literal,TypedDict, Annotated, Sequence,List,Optional
from langchain_core.messages import SystemMessage, RemoveMessage,HumanMessage
import re
import datetime
import psycopg2
from langgraph.checkpoint.memory import MemorySaver
from opensearchpy import OpenSearch, RequestsHttpConnection
from requests_aws4auth import AWS4Auth
import boto3
import requests
import logging
import os
from langchain_core.messages import BaseMessage
from typing_extensions import TypedDict
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode

from langchain_aws import ChatBedrock
from langchain_core.prompts import ChatPromptTemplate
from langchain_aws import ChatBedrockConverse
import operator
from langchain_core.messages import BaseMessage
from langchain.chains import LLMChain
from langchain.output_parsers import OutputFixingParser
from langchain.output_parsers import PydanticOutputParser
from pydantic import BaseModel , Field
from langchain.prompts import PromptTemplate
from langchain.vectorstores import OpenSearchVectorSearch
from langchain_aws import BedrockEmbeddings
from opensearchpy import RequestsHttpConnection, AWSV4SignerAuth
from app.core.logging import configure_logging
from app.core.config import get_config
import json
import yaml

config = get_config() 
aws_config = config["aws"]
s3_config = config["aws"]["s3"]
opensearch_config = config["aws"]["opensearch"]
bedrock_config = config["aws"]["bedrock"]
# Logger
logger = configure_logging()

# AWS credentials
aws_access_key = aws_config["credentials"]["access_key_id"]
aws_secret_key = aws_config["credentials"]["secret_access_key"]
aws_session_token = aws_config["credentials"].get("session_token", "")
region = aws_config["region"]

# S3 bucket and object
bucket_name = s3_config["bucket_name"]
object_key = s3_config["object_key"]

# OpenSearch settings
opensearch_url = opensearch_config["url"]
index_name = opensearch_config["index_name"]

# Bedrock LLM
bedrock_model_id = bedrock_config["model_id"]
bedrock_temperature = bedrock_config["temperature"]

memory = MemorySaver()

class State(MessagesState):
    summary:str

session = boto3.Session(
    aws_access_key_id=aws_access_key,
    aws_secret_access_key=aws_secret_key,
    aws_session_token=aws_session_token,
    region_name="us-east-1"
)

# Create the Bedrock client
bedrock = session.client(service_name="bedrock-runtime")
llm = ChatBedrockConverse(
    model="anthropic.claude-3-sonnet-20240229-v1:0",
    temperature = 0,
    max_tokens=None,
    client = bedrock
)

def fetch_from_opensearch(query, opensearch_url, index_name, aws_access_key, aws_secret_key, aws_session_token, region="us-east-1"):
    """
    Fetch relevant data from OpenSearch based on a semantic search query using Bedrock Embeddings and LangChain.
    Parses the results into structured fields.
    """
    
    bedrock = session.client(service_name="bedrock-runtime")
    embeddings = BedrockEmbeddings(model_id="amazon.titan-embed-text-v2:0", client=bedrock)

    # Set up OpenSearch connection
    credentials = boto3.Session().get_credentials()
    auth = AWSV4SignerAuth(credentials, region, "aoss")
    oss = OpenSearchVectorSearch(
        opensearch_url=opensearch_url,
        index_name=index_name,
        embedding_function=embeddings,
        http_auth=auth,
        use_ssl=True,
        verify_certs=True,
        connection_class=RequestsHttpConnection,
    )
    # Perform semantic search
    results = oss.similarity_search(query=query.content, k=1)  # Adjust `k` for number of results

    # Parse results into structured fields
    structured_results = []
    for result in results:
        content = result.page_content
        # Extract fields from page_content
        fields = {}
        for line in content.split("."):
            if ":" in line:
                key, value = line.split(":", 1)
                fields[key.strip()] = value.strip()
        # Add only the required fields
        structured_result = {
            "threat_category": fields.get("threat_category"),
            # "Category": fields.get("Category"),
            # "category_uid": fields.get("category_uid"),
            # "Class": fields.get("Class"),
            # "class_uid": fields.get("class_uid"),
            "message_description": fields.get("message_description"),
            "required_action": fields.get("required_action"),
            "threat_id": fields.get("threat_id"),
        }
        structured_results.append(structured_result)

    return structured_results


def fetch_by_threat_category(threat_category):
    """
    Query the DynamoDB table to fetch rows based on threat_category.

    Args:
        threat_category (str): The threat category to query.

    Returns:
        dict: A dictionary containing additional details for the given threat_category.
    """
    dynamodb = boto3.client('dynamodb', region_name='us-east-1')
    table_name = "reverse-index-lookup-template-updated"

    #try:
    response = dynamodb.query(
        TableName=table_name,
        KeyConditionExpression="threat_category = :category",
        ExpressionAttributeValues={
            ":category": {"S": threat_category}  # "S" for string type
        }
    )
    if response.get('Items'):
        item = response['Items'][0]  # Assuming one result per category

        # Parse the returned item
        return {
            "category_uid": item.get("category_uid", {}).get("N"),
            "required_subset": item.get("required_subset", {}).get("S"),
            "class_uid": item.get("class_uid", {}).get("N"),
            "bu": item.get("bu", {}).get("S"),
            "required_indexing": item.get("required_indexing", {}).get("S"),
            "class_name": item.get("class_name", {}).get("S"),
            "category_name": item.get("category", {}).get("S"),
            "fetch_subset_columns": eval(item.get("fetch_subset_columns", {}).get("S", "[]")),  # Safely evaluate the list
            "threat_severity": item.get("threat_severity", {}).get("S"),
            # "period": {
            #     "years": int(item.get("period", {}).get("M", {}).get("years", {}).get("N", "0"))
            # },
            "period": item.get("period", {}).get("M"),
            "required_relational": item.get("required_relational", {}).get("S"),
            "threat_category": item.get("threat_category", {}).get("S"),
        }
    return {}

    # except Exception as e:
    #     print(f"Error querying DynamoDB: {e}")
    #     return {}

def get_class_schema_from_s3(bucket_name, object_key, category_name, class_name):
    """
    Retrieve the schema for a specific class under a given category from JSON stored in an S3 bucket.

    Args:
        bucket_name (str): The name of the S3 bucket.
        object_key (str): The key (file path) of the JSON file in the S3 bucket.
        category_name (str): The name of the category to search for.
        class_name (str): The name of the class to retrieve the schema for.

    Returns:
        list: The schema of the specified class, or None if not found.
    """
    #try:
    # Category name mapping
    category_name_mapping = {
        "System Activity": "system",
        "Application Activity": "application",
        "Findings": "findings",
        "Identity & Access Management": "iam",
        "Network Activity": "network",
        "Discovery": "discovery",
        "Remediation": "remediation",
    }

    normalized_category_name = category_name_mapping.get(category_name.strip(), category_name.strip())
    print(f"Normalized category name: {normalized_category_name}")

    # Convert class name to lowercase with underscores
    normalized_class_name = class_name.strip().lower().replace(" ", "_")
    print(f"Normalized class name: {normalized_class_name}")
    # Initialize S3 client
    s3 = boto3.client('s3')

    # Fetch the JSON file from S3
    response = s3.get_object(Bucket="hpe-data-fabric-genai", Key="OCSF_schema_v2.json")
    json_data = response['Body'].read().decode('utf-8')
    # print(response)
    # Parse the JSON data
    data = json.loads(json_data)
    # print(data)
    # print(normalized_category_name,normalized_class_name)
    # Iterate through the categories
    for category in data.get("categories", []):
        if category.get("category_name") == normalized_category_name:
            # Iterate through the classes within the category
            for class_item in category.get("classes", []):
                if class_item.get("class_name") == normalized_class_name:
                    return class_item.get("schema", [])
    
    # If no match is found
    return None

    # except Exception as e:
    #     print(f"Error occurred: {e}")
    #     return None


def fetch_and_enrich(query, opensearch_url, index_name, aws_access_key, aws_secret_key, aws_session_token, region, bucket_name, object_key):
    # Fetch data from OpenSearch
    search_results = fetch_from_opensearch(query, opensearch_url, index_name, aws_access_key, aws_secret_key, aws_session_token, region)

    # Enrich data with DynamoDB details and S3 schema
    enriched_results = []
    for result in search_results:
        threat_category = result.get("threat_category")
        if threat_category:
            print("inside threat_category",threat_category)
            additional_data = fetch_by_threat_category(threat_category)
            if additional_data:
                result.update(additional_data)
                print("5"*4)
                templete = f"""You are tasked with matching the most similar class name from the provided example list.

                Instructions:
                Take the potential class name as input.
                Identify the most relevant class name from the given categories and their respective class names.
                Output only the most matching class name as a single string (e.g., file_activity).
                Example Input:
                Potential class name: {additional_data.get("class_name")}
                
                Categories and Class Names:
                System: [process_activity, scheduled_job_activity, file_activity, memory_activity, kernel_extension, kernel_activity, event_log, module_activity, resource_activity, registry_key_activity, registry_value_activity, win_service_activity]
                Application: [datastore_activity, application_lifecycle, api_activity, file_hosting, web_resource_access_activity, scan_activity, web_resources_activity]
                Findings: [incident_finding, security_finding, data_security_finding, detection_finding, compliance_finding, vulnerability_finding]
                IAM: [authentication, account_change, authorize_session, entity_management, group_management, user_access]
                Network: [rdp_activity, tunnel_activity, smb_activity, dhcp_activity, network_file_activity, email_url_activity, email_activity, ftp_activity, email_file_activity, network_activity, ssh_activity, dns_activity, http_activity, ntp_activity]
                Discovery: [admin_group_query, session_query, networks_query, device_config_state_change, kernel_object_query, file_query, software_info, folder_query, user_query, user_inventory, network_connection_query, module_query, process_query, inventory_info, config_state, service_query, job_query, peripheral_device_query, patch_state, registry_key_query, registry_value_query, prefetch_query]
                Remediation: [remediation_activity, file_remediation_activity, network_remediation_activity, process_remediation_activity]
                Expected Output:
                Output only the most similar class name as a single string.
                """
                prompt = PromptTemplate(template=templete,
                                    input_variables=[additional_data.get("class_name")])
                                    # partial_variables={
                                    #     "format_instructions" : parser.get_format_instructions()                                    }
                                    # )
                chain = prompt | llm
            
                response = chain.invoke({"classname":additional_data.get("class_name")})
            
                print("response from the llm",response.content)
                # Fetch schema from S3
                schema = get_class_schema_from_s3(
                    bucket_name=bucket_name,
                    object_key=object_key,
                    category_name=additional_data.get("category_name"),
                    class_name=response.content,
                )
                if schema:
                    result["schema"] = schema
                else:
                    print(f"No schema found for category: {additional_data.get('category_name')} and class: {additional_data.get('class_name')}")
            else:
                print(f"No data found in DynamoDB for threat_category: {threat_category}")
        else:
            print("Skipping DynamoDB query due to missing threat_category.")
        enriched_results.append(result)

    return enriched_results
def fetch_index_id_from_dynamodb(category_uid, class_uid, table_name="hpe_sdf_reverse_indexing_lookup_status"):
    """
    Query the DynamoDB table to fetch rows containing dynamically generated index_id parts.

    Args:
        category_uid (str): The category UID from the JSON.
        class_uid (str): The class UID from the JSON.
        table_name (str): The DynamoDB table name.

    Returns:
        list: A list of matching items from the DynamoDB table.
    """
    dynamodb = boto3.client('dynamodb', region_name='us-east-1')

    # Dynamically generate the index ID part
    dynamic_index_part = f"cloud_trail_mgmt_{category_uid}_{class_uid}"

    try:
        # Scan the table for items containing the dynamic index part
        response = dynamodb.scan(
            TableName="hpe_sdf_reverse_indexing_lookup_status",
            FilterExpression="contains(index_id, :index_part)",
            ExpressionAttributeValues={
                ":index_part": {"S": dynamic_index_part}
            }
        )

        # Return the matching items
        return response.get("Items", [])

    except Exception as e:
        print(f"Error querying DynamoDB for index_id: {e}")
        return []
    
# def fetch_index_id_from_dynamodb(category_uid, class_uid, table_name="hpe_sdf_reverse_indexing_lookup_status"):
#     """
#     Query the DynamoDB table to fetch rows containing dynamically generated index_id parts.

#     Args:
#         category_uid (str): The category UID from the JSON.
#         class_uid (str): The class UID from the JSON.
#         table_name (str): The DynamoDB table name.

#     Returns:
#         list: A list of matching items from the DynamoDB table.
#     """
#     dynamodb = boto3.client('dynamodb', region_name='us-east-1')

#     # Dynamically generate the index ID part
#     dynamic_index_part = f"cloud_trail_mgmt_{category_uid}_{class_uid}"

#     try:
#         # Scan the table for items containing the dynamic index part
#         response = dynamodb.scan(
#             TableName="hpe_sdf_reverse_indexing_lookup_status",
#             FilterExpression="contains(index_id, :index_part)",
#             ExpressionAttributeValues={
#                 ":index_part": {"S": dynamic_index_part}
#             }
#         )

#         # Return the matching items
#         return response.get("Items", [])

#     except Exception as e:
#         print(f"Error querying DynamoDB for index_id: {e}")
#         return []
def process_dynamodb_response(response):
    """
    Process the DynamoDB response to structure it into JSON format.

    Args:
        response (list): List of items from DynamoDB.

    Returns:
        dict: Structured JSON with Athena table names, OpenSearch table names, Redshift table names, and index IDs.
    """
    result = {
        "index_ids": [],
        "athena_table_names": [],
        "open_search_table_names": [],
        "redshift_table_names": []
    }

    for item in response:
        index_id = item.get('index_id', {}).get('S')
        athena_table_name = item.get('athena_table_name', {}).get('S')
        open_search_table_name = item.get('open_search_index_name', {}).get('S')
        redshift_table_name = item.get('redshift_table', {}).get('S')

        if index_id:
            result["index_ids"].append(index_id)
        if athena_table_name:
            result["athena_table_names"].append(athena_table_name)
        if open_search_table_name:
            result["open_search_table_names"].append(open_search_table_name)
        if redshift_table_name:
            result["redshift_table_names"].append(redshift_table_name)

    return result
def fetch_athena_table_schema(database_name, table_name):
    """
    Fetch the schema of an Athena table.

    Args:
        database_name (str): The name of the Athena database.
        table_name (str): The name of the Athena table.

    Returns:
        dict: The schema of the Athena table (columns and their types).
    """
    # # Initialize Athena client
    # athena_client = boto3.client("glue", region_name="us-east-1")

    # # Fetch table metadata
    # response = athena_client.get_table(DatabaseName=database_name, Name=table_name)

    # # Extract schema details
    # columns = response["Table"]["StorageDescriptor"]["Columns"]
    # schema = {col["Name"]: col["Type"] for col in columns}
    schema = {
        "metadata_product_version": "string",
        "metadata_product_name": "string",
        "metadata_product_vendor_name": "string",
        "metadata_product_feature_name": "string",
        "metadata_event_code": "string",
        "metadata_uid": "string",
        "metadata_profiles": "array<string>",
        "metadata_version": "string",
        "time": "bigint",
        "time_dt": "timestamp",
        "cloud_region": "string",
        "cloud_provider": "string",
        "api_response_error": "string",
        "api_response_message": "string",
        "api_response_data": "string",
        "api_operation": "string",
        "api_version": "string",
        "api_service_name": "string",
        "api_request_data": "string",
        "api_request_uid": "string",
        "dst_endpoint_svc_name": "string",
        "actor_user_type": "string",
        "actor_user_name": "string",
        "actor_user_uid_alt": "string",
        "actor_user_uid": "string",
        "actor_user_account_uid": "string",
        "actor_user_credential_uid": "string",
        "actor_session_created_time_dt": "timestamp",
        "actor_session_is_mfa": "boolean",
        "actor_session_issuer": "string",
        "actor_invoked_by": "string",
        "actor_idp_name": "string",
        "http_request_user_agent": "string",
        "src_endpoint_uid": "string",
        "src_endpoint_ip": "string",
        "src_endpoint_domain": "string",
        "session_uid": "string",
        "session_uid_alt": "string",
        "session_credential_uid": "string",
        "session_issuer": "string",
        "policy_uid": "string",
        "resources_exploded": "struct<uid:string,owner:struct<account:struct<uid:string>>,type:string>",
        "class_name": "string",
        "class_uid": "int",
        "category_name": "string",
        "category_uid": "int",
        "severity_id": "int",
        "severity": "string",
        "user_uid_alt": "string",
        "user_uid": "string",
        "user_name": "string",
        "activity_name": "string",
        "activity_id": "int",
        "type_uid": "bigint",
        "type_name": "string",
        "status": "string",
        "is_mfa": "boolean",
        "unmapped": "map<string,string>",
        "accountid": "string",
        "region": "string",
        "asl_version": "string",
        "observables_exploded": "struct<name:string,value:string,type:string,type_id:int>",
        "filter_tag": "string",
        "severity_class": "string",
        "threat_category": "string",
        "index_id": "string"
    }
    return schema
# Define the logic to call the model
def call_model(state: State):
    # If a summary exists, we add this in as a system message
    summary = state.get("summary", "")
    print("this is the summary",summary)
    if summary:
        system_message = f"Summary of conversation earlier: {summary}"
        messages = [SystemMessage(content=system_message)] + state["messages"]
        response = llm.invoke(messages)
        print(type(response))
    else:
        messages = state["messages"]
        response = ''
    # We return a list, because this will get added to the existing list
    return {"messages": [response]}
# We now define the logic for determining whether to end or summarize the conversation
def should_continue(state: State):
    """Return the next node to execute."""
    messages = state["messages"]
    print("this is the messages from should_continue",messages)
    print("this is length if messages from should continue",len(messages))
    # If there are more than six messages, then we summarize the conversation
    if len(messages) > 2:
        print("--summarization of conversation and integrate with the schema--")
        return "summarize_conversation"
    elif len(messages)<=2:
        print("--determine the category and fetch other metadata")
        return "determine_category"
    # Otherwise we can just end
    return END

def determine_category(state: State):
    messages = state['messages']
    print("this is the entire messages",messages)
    question = messages[0]   ## Fetching the user question
    print("this is a question",question)
    # Fetch and enrich data
    final_results = fetch_and_enrich(question, opensearch_url, index_name, aws_access_key, aws_secret_key, aws_session_token, region,bucket_name,object_key)
    category_uid=""
    class_uid=""
    # Print the final enriched JSON
    print("Final Results:")
    for idx, result in enumerate(final_results, start=1):
        print(f"\nResult {idx}:")
        print(result)
        category_uid=result['category_uid']
        class_uid=result['class_uid']
    category_uid = "6"
    class_uid = "6007"

    # Fetch matching rows from the DynamoDB table
    matching_rows = fetch_index_id_from_dynamodb(category_uid, class_uid, table_name="index-id-table")
    structured_json = process_dynamodb_response(matching_rows)
    athena_table_name = structured_json["athena_table_names"][0]
    print("athena table name",athena_table_name)
    database_name = "db"  # Replace with your Athena database name

    # Fetch the schema of the first Athena table
    schema = fetch_athena_table_schema(database_name, athena_table_name)
    print("athena table schema",schema)
    # Create a formatted message string
    message_content = f"""
    Threat Category: {result['threat_category']}
    Description: {result['message_description']}
    Required Action: {result['required_action']}
    Threat ID: {result['threat_id']}
    Severity: {result['threat_severity']}
    OCSFSchema: {result['schema']}
    athenatablename: {athena_table_name}
    athenatableschema: {schema}
    
    
    """
    return {
        "messages": [{
            "role": "assistant",  # or "user" depending on your use case
            "content": message_content
        }]
    }
    #return {"messages": [result]}

def summarize_conversation(state: State):
    # First, we summarize the conversation
    summary = state.get("summary", "")
    if summary:
        # If a summary already exists, we use a different system prompt
        # to summarize it than if one didn't
        summary_message = (
            f"This is summary of the conversation to date: {summary}\n\n"
            "Extend the summary by taking into account the new messages above:"
        )
    else:
        summary_message = "Create a summary of the conversation above:"

    messages = state["messages"] + [HumanMessage(content=summary_message)]
    response = llm.invoke(messages)
    # We now need to delete messages that we no longer want to show up
    # I will delete all but the last two messages, but you can change this
    delete_messages = [RemoveMessage(id=m.id) for m in state["messages"][:-2]]
    return {"summary": response.content, "messages": delete_messages}

def generate_sql_query(state: State):
    messages = state.get('messages', [])
    print("This is messages from generate_sql_query", messages)

    question = messages[0].content
    print("question",question)
    for message in messages:
        if "athenatablename" in message.content:
            athenatablename = message.content.split("athenatablename: ")[1].split("\n")[0]
            athenatableschema = yaml.safe_load(message.content.split("athenatableschema: ")[1].split("\n")[0])
            OCSFSchema = yaml.safe_load(message.content.split("OCSFSchema: ")[1].split("\n")[0])
            print("athenatablename:", athenatablename)
            print("athenatableschema:", athenatableschema)
            print("OCSFSchema:", OCSFSchema)
    
    template = """
    You are an expert SQL query generator specialized in Amazon Athena. Your task is to generate a precise and valid SQL query based on the user's question, leveraging the provided Athena table name, schema, and OCSFJSON information.

    Instructions:
    Use the Athena Table Name and Athena Table Schema to construct the query.
    Refer to the OCSFJSON Information for detailed descriptions of the schema columns and type to ensure accuracy.
    The SQL query must:
    Be syntactically correct and optimized for Athena.
    Address the user's question comprehensively and precisely.
    Use appropriate column names and data types based on the schema.
    Input Details:
    User Question: {question}
    Athena Table Name: {athena_table_name}
    OCSFJSON Information: {json_info}
    Athena Table Schema: {schema}
    
    Output:
    Provide only the generated SQL query as the output, without any additional explanation or commentary.

    """

    # Output parser to fix formatting issues (optional)
    # parser = OutputFixingParser.from_defaults(output_type=str)

    # Define the prompt
    prompt = PromptTemplate(
        template=template,
        input_variables=["question", "athena_table_name", "json_info", "schema"],
        # partial_variables={"format_instructions": parser.get_format_instructions()}
    )

    # Define the LLM
    bedrock = session.client(service_name="bedrock-runtime")
    llm = ChatBedrockConverse(
        model="anthropic.claude-3-sonnet-20240229-v1:0",
        temperature = 0,
        max_tokens=None,
        client = bedrock
    )

    # Create the chain
    # chain = prompt | llm | parser
    chain= LLMChain(llm=llm, prompt=prompt)

    # Call the chain with all variables
    response = chain.run({
        "question": question,
        "athena_table_name": athenatablename,
        "json_info": OCSFSchema,
        "schema": athenatableschema
    })

    return {"messages": [response]}
class ConversationGraph:
    def __init__(self):
        self.app = None
        self.memory = None
        self.config = {"configurable": {"thread_id": "1"}}
        
    def initialize_graph(self):
        # Initialize memory
        self.memory = None
        
        # Define graph
        workflow = StateGraph(State)
        
        # Add nodes
        workflow.add_node("conversation", call_model)
        workflow.add_node(summarize_conversation)
        workflow.add_node("determine_category", determine_category)
        workflow.add_node("generate_sql_query", generate_sql_query)
        
        # Define edges
        workflow.add_edge(START, "conversation")
        workflow.add_conditional_edges(
            "conversation",
            should_continue,
        )
        workflow.add_edge("determine_category", "generate_sql_query")
        workflow.add_edge("generate_sql_query", END)
        workflow.add_edge("summarize_conversation", END)
        
        # Compile graph
        self.app = workflow.compile(checkpointer=self.memory)
        
    def process_message(self, user_input: str):
        if self.app is None:
            self.initialize_graph()
            
        # Process the message
        result = self.app.invoke(
            {"messages": [HumanMessage(content=user_input)]},
            self.config
        )
        return result["messages"][-1].content

# Usage example:
graph = ConversationGraph()

# # First use - will initialize the graph
# response = graph.process_message("how many unauthorized access alerts are there in last 10 days?")
# print("Response 1:", response)