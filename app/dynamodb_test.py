from app.db.dynamodb import get_dynamodb_client

def test_create_users_table():
    try:
        dynamodb = get_dynamodb_client()
        table_name = "Users"
        
        # Create the Users table
        table = dynamodb.create_table(
            TableName=table_name,
            KeySchema=[
                {'AttributeName': 'user_id', 'KeyType': 'HASH'}  # Partition key
            ],
            AttributeDefinitions=[
                {'AttributeName': 'user_id', 'AttributeType': 'S'}
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 5,
                'WriteCapacityUnits': 5
            }
        )

        # Wait until the table is created
        print(f"Creating table '{table_name}'...")
        table.meta.client.get_waiter('table_exists').wait(TableName=table_name)
        print(f"Table '{table_name}' created successfully.")
        return table
    except Exception as e:
        print(f"Error creating table: {str(e)}")


def test_list_tables():
    try:
        dynamodb = get_dynamodb_client()
        tables = list(dynamodb.tables.all())
        print("Tables in DynamoDB:")
        for table in tables:
            print(f"- {table.name}")
    except Exception as e:
        print(f"Error listing tables: {str(e)}")


if __name__ == "__main__":
    # Test table creation
    test_create_users_table()

    # Test listing tables
    test_list_tables()
