import boto3
import time
from app.core.config import get_config
from botocore.exceptions import ClientError
from app.core.logging import configure_logging

logger = configure_logging()
config = get_config()
### HELPERS ####
def get_dynamodb_client():
    aws_credentials = config['aws']['credentials']
    region = config['aws']['region']

    return boto3.resource(
        'dynamodb',
        region_name=region,
        aws_access_key_id=aws_credentials['access_key_id'],
        aws_secret_access_key=aws_credentials['secret_access_key'],
        aws_session_token=aws_credentials.get('session_token')  # Optional, for temporary credentials
    )


def check_table_exists(table_name):
    dynamodb = get_dynamodb_client()
    try:
        table = dynamodb.Table(table_name)
        table.load()  # Attempt to load the table's metadata
        return True
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            return False
        raise


def wait_for_table_active(table_name):
    """
    Waits until the specified DynamoDB table is in ACTIVE state.
    """
    dynamodb = get_dynamodb_client()
    table = dynamodb.Table(table_name)
    while True:
        try:
            table.load()  # Loads the table metadata
            if table.table_status == "ACTIVE":
                print(f"Table {table_name} is ACTIVE.")
                break
            else:
                print(f"Table {table_name} is still {table.table_status}...")
        except ClientError as e:
            if e.response['Error']['Code'] == "ResourceNotFoundException":
                print(f"Table {table_name} not yet created. Retrying...")
            else:
                raise
        time.sleep(2)  # Wait for 2 seconds before retrying



### TABLE CREATION #######
def create_users_table():
    table_name = config['aws']['dynamodb']['users_table']
    if not check_table_exists(table_name):
        dynamodb = get_dynamodb_client()
        table = dynamodb.create_table(
            TableName=table_name,
            KeySchema=[
                {'AttributeName': 'user_id', 'KeyType': 'HASH'}
            ],
            AttributeDefinitions=[
                {'AttributeName': 'user_id', 'AttributeType': 'S'}
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 5,
                'WriteCapacityUnits': 5
            }
        )
        print(f"Table {table_name} is being created. Status: {table.table_status}")
        wait_for_table_active(table_name)
    else:
        print(f"Table {table_name} already exists.")

def create_assistants_table():
    table_name = config['aws']['dynamodb']['assistants_table']
    if not check_table_exists(table_name):
        dynamodb = get_dynamodb_client()
        table = dynamodb.create_table(
            TableName=table_name,
            KeySchema=[
                {'AttributeName': 'user_id', 'KeyType': 'HASH'},
                {'AttributeName': 'assistant_id', 'KeyType': 'RANGE'}
            ],
            AttributeDefinitions=[
                {'AttributeName': 'user_id', 'AttributeType': 'S'},
                {'AttributeName': 'assistant_id', 'AttributeType': 'S'}
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 5,
                'WriteCapacityUnits': 5
            }
        )
        wait_for_table_active(table_name)
        print(f"Table {table_name} created successfully.")
    
def create_chat_sessions_table():
    table_name = config['aws']['dynamodb']['chat_sessions_table']
    if not check_table_exists(table_name):
        try:
            dynamodb = get_dynamodb_client()
            table = dynamodb.create_table(
                TableName=table_name,
                KeySchema=[
                    {'AttributeName': 'assistant_id', 'KeyType': 'HASH'},
                    {'AttributeName': 'session_id', 'KeyType': 'RANGE'}
                ],
                AttributeDefinitions=[
                    {'AttributeName': 'assistant_id', 'AttributeType': 'S'},
                    {'AttributeName': 'session_id', 'AttributeType': 'S'}
                ],
                ProvisionedThroughput={
                    'ReadCapacityUnits': 5,
                    'WriteCapacityUnits': 5
                }
            )
            wait_for_table_active(table_name)
            logger.info(f"Table {table_name} created successfully.")
        except Exception as e:
            logger.error(f"Error creating {table_name} table: {e}")
            raise Exception("Failed to create ChatSessions table.")

def create_chat_messages_table():
    table_name = config['aws']['dynamodb']['chat_messages_table']
    if not check_table_exists(table_name):
        try:
            dynamodb = get_dynamodb_client()
            table = dynamodb.create_table(
                TableName=table_name,
                KeySchema=[
                    {'AttributeName': 'chat_session_id', 'KeyType': 'HASH'},
                    {'AttributeName': 'message_id', 'KeyType': 'RANGE'}
                ],
                AttributeDefinitions=[
                    {'AttributeName': 'chat_session_id', 'AttributeType': 'S'},
                    {'AttributeName': 'message_id', 'AttributeType': 'S'}
                ],
                ProvisionedThroughput={
                    'ReadCapacityUnits': 5,
                    'WriteCapacityUnits': 5
                }
            )
            wait_for_table_active(table_name)
            logger.info(f"Table {table_name} created successfully.")
        except Exception as e:
            logger.error(f"Error creating {table_name} table: {e}")
            raise Exception("Failed to create ChatMessages table.")


#### DB INTERACTIONS ##########
def get_user_by_name(user_name):
    table_name = config['aws']['dynamodb']['users_table']
    dynamodb = get_dynamodb_client()
    table = dynamodb.Table(table_name)

    try:
        # Query the table using user_name as a filter
        response = table.scan(
            FilterExpression="user_name = :user_name",
            ExpressionAttributeValues={":user_name": user_name}
        )
        items = response.get('Items', [])
        return items[0] if items else None
    except ClientError as e:
        print(f"Error querying user by name: {e}")
        raise Exception("Error querying the database.")
    
def create_user(user_data):
    table_name = config['aws']['dynamodb']['users_table']
    dynamodb = get_dynamodb_client()
    table = dynamodb.Table(table_name)

    try:
        # Insert the user data
        table.put_item(Item=user_data)
        print(f"User {user_data['user_name']} added successfully.")
    except ClientError as e:
        print(f"Error creating user: {e}")
        raise Exception("Error writing to the database.")
    
#Assistants
def get_assistants(user_id: str):
    """
    Fetch all assistants for a specific user.
    """
    table_name = config['aws']['dynamodb']['assistants_table']
    dynamodb = get_dynamodb_client()
    table = dynamodb.Table(table_name)

    try:
        response = table.query(
            KeyConditionExpression="user_id = :u",
            ExpressionAttributeValues={":u": user_id}
        )
        return response.get('Items', [])
    except ClientError as e:
        print(f"Error querying assistants for user {user_id}: {e}")
        raise Exception("Error querying the database.")
    
def create_assistant(assistant_data: dict):
    """
    Create a new assistant in the Assistants table.
    """
    table_name = config['aws']['dynamodb']['assistants_table']
    dynamodb = get_dynamodb_client()
    table = dynamodb.Table(table_name)

    try:
        table.put_item(Item=assistant_data)
        print(f"Assistant {assistant_data['assistant_name']} created successfully for user {assistant_data['user_id']}.")
    except ClientError as e:
        print(f"Error creating assistant: {e}")
        raise Exception("Error writing to the database.")
    

#chat_sessions

def get_chat_sessions(assistant_id: str, user_id: str):
    """
    Fetch all chat sessions for a specific assistant and user.
    """
    table_name = config['aws']['dynamodb']['chat_sessions_table']
    dynamodb = get_dynamodb_client()
    table = dynamodb.Table(table_name)

    try:
        response = table.query(
            KeyConditionExpression="assistant_id = :a",
            FilterExpression="user_id = :u",
            ExpressionAttributeValues={
                ":a": assistant_id,
                ":u": user_id
            }
        )
        return response.get('Items', [])
    except ClientError as e:
        logger.error(f"Error querying chat sessions for assistant {assistant_id} and user {user_id}: {e}")
        raise Exception("Error querying the database.")
    

def create_chat_session(chat_session_data: dict):
    """
    Create a new chat session in the ChatSessions table.
    """
    table_name = config['aws']['dynamodb']['chat_sessions_table']
    dynamodb = get_dynamodb_client()
    table = dynamodb.Table(table_name)

    try:
        table.put_item(Item=chat_session_data)
        logger.info(f"Chat session {chat_session_data['session_id']} created successfully for assistant {chat_session_data['assistant_id']}.")
    except ClientError as e:
        logger.error(f"Error creating chat session: {e}")
        raise Exception("Error writing to the database.")
    

#chat_message & Query 

def get_chat_messages(chat_session_id: str):
    """
    Fetch all messages for a specific chat session.
    """
    table_name = config['aws']['dynamodb']['chat_messages_table']
    dynamodb = get_dynamodb_client()
    table = dynamodb.Table(table_name)

    try:
        response = table.query(
            KeyConditionExpression="chat_session_id = :c",
            ExpressionAttributeValues={":c": chat_session_id}
        )
        return response.get('Items', [])
    except ClientError as e:
        logger.error(f"Error fetching messages for chat session {chat_session_id}: {e}")
        raise Exception("Error querying the database.")
    
def save_chat_message(message_data: dict):
    """
    Save a message to the ChatMessages table.
    """
    table_name = config['aws']['dynamodb']['chat_messages_table']
    dynamodb = get_dynamodb_client()
    table = dynamodb.Table(table_name)

    try:
        table.put_item(Item=message_data)
        logger.info(f"Message {message_data['message_id']} saved to chat session {message_data['chat_session_id']}.")
    except ClientError as e:
        logger.error(f"Error saving message to chat session {message_data['chat_session_id']}: {e}")
        raise Exception("Error writing to the database.")