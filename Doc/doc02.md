# Sending a POST Request-Tx

This guide will walk you through sending a POST request in Postman. Before sending the request, you'll need to fetch specific token IDs and network IDs from different endpoints. Here's how to do it step by step:

## Prerequisites

Add necessary variable to .env file. See .env.example necessary variables

## Authentication Setup

1. **Make up the user account:**
   - Inside the '.env' file, fill in the 
    </br>SECRET_KEY,
    </br>PUBLIC_KEY,
    </br>HSM_PATH="http://127.0.0.1:7000"

## Broadcast Request Setup
Send POST request to 127.0.0.1:8000/broadcast-tx with raw json body of 
```
{
    "id": "tx_id",
    "hash": "tx_hash_after_perform_transaction"
}
```
## Expected Response
```
{
    "data": {
        "Transaction ID": "tx_id",
        "Transaction hash": "broadcast",
        "Transaction status": "broadcast_status"
    },
    "status": "status"
}
```