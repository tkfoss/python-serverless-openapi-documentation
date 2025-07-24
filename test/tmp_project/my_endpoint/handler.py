def lambda_handler(event, context):
    """
    A simple lambda handler.
    """
    return {
        "statusCode": 200,
        "body": "Hello from Lambda!"
    }
