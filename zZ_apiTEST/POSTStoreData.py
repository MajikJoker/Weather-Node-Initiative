import requests
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def sign_data(private_key, data):
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

# Generate key pair and sign data
private_key, public_key = generate_key_pair()
data = b"example weather data"
signature = sign_data(private_key, data)

# Prepare the data to be sent
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

payload = {
    'data': data.decode('latin1'),
    'signature': signature.decode('latin1'),
    'public_key': public_key_pem.decode('utf-8')
}

# Print the secured data before sending
print("Data in transit:")
print(f"Data: {data.decode('latin1')}")
print(f"Signature: {signature.decode('latin1')}")
print(f"Public Key PEM: {public_key_pem.decode('utf-8')}")

# Send the POST request to store the data
response = requests.post('http://127.0.0.1:5000/store-data', json=payload)
response_data = response.json()

# Save the transaction ID to a file
with open('transaction_id.txt', 'w') as file:
    file.write(response_data['transaction_id'])

print(response_data)
