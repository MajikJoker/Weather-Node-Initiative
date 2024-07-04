from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from hashlib import sha256
import os

app = Flask(__name__)
transactions = {}

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

def hash_data(data):
    return sha256(data).hexdigest()

def generate_transaction_id():
    return os.urandom(16).hex()

def store_data_in_db(data, signature, public_key):
    data_hash = hash_data(data)
    signature_hash = hash_data(signature)
    transaction_id = generate_transaction_id()
    
    transactions[transaction_id] = {
        'data': data,
        'signature': signature,
        'public_key': public_key,
        'data_hash': data_hash,
        'signature_hash': signature_hash
    }
    print(f"Stored transaction: {transaction_id}")

def verify_signature(public_key, data, signature):
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(e)
        return False

def verify_integrity(transaction_id):
    if transaction_id not in transactions:
        return False, "Transaction ID not found"
    
    transaction = transactions[transaction_id]
    stored_data_hash = transaction['data_hash']
    stored_signature_hash = transaction['signature_hash']
    
    current_data_hash = hash_data(transaction['data'].encode('latin1'))
    current_signature_hash = hash_data(transaction['signature'].encode('latin1'))
    
    if stored_data_hash != current_data_hash:
        return False, "Data hash mismatch, data may have been tampered"
    
    if stored_signature_hash != current_signature_hash:
        return False, "Signature hash mismatch, signature may have been tampered"
    
    public_key = serialization.load_pem_public_key(transaction['public_key'].encode('utf-8'))
    is_valid = verify_signature(public_key, transaction['data'].encode('latin1'), transaction['signature'].encode('latin1'))
    
    if not is_valid:
        return False, "Signature verification failed, data integrity compromised"
    
    return True, "Data integrity verified successfully"

@app.route('/store-data', methods=['POST'])
def store_data():
    data = request.json['data'].encode('latin1')
    signature = request.json['signature'].encode('latin1')
    public_key_pem = request.json['public_key'].encode('utf-8')
    
    data_hash = hash_data(data)
    signature_hash = hash_data(signature)
    transaction_id = generate_transaction_id()
    
    transactions[transaction_id] = {
        'data': data.decode('latin1'),
        'signature': signature.decode('latin1'),
        'public_key': public_key_pem.decode('utf-8'),
        'data_hash': data_hash,
        'signature_hash': signature_hash
    }
    
    print(f"Data stored with transaction_id: {transaction_id}")
    return jsonify({'status': 'success', 'transaction_id': transaction_id})

@app.route('/verify-data', methods=['GET'])
def verify_data():
    transaction_id = request.args.get('transaction_id')
    print(f"Verifying transaction_id: {transaction_id}")
    is_valid, message = verify_integrity(transaction_id)
    
    if is_valid:
        transaction = transactions[transaction_id]
        print("Cleartext message:")
        print(transaction['data'])

    status = 'success' if is_valid else 'error'
    return jsonify({'status': status, 'message': message})


if __name__ == '__main__':
    app.run(debug=True)
