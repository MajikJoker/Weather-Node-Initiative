import requests

# Read the transaction ID from the file
with open('transaction_id.txt', 'r') as file:
    transaction_id = file.read().strip()

print(f"Transaction ID: {transaction_id}")

# Send the GET request to verify the data
response = requests.get(f'http://127.0.0.1:5000/verify-data?transaction_id={transaction_id}')
print(response.json())
