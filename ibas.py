import hashlib

# Helper functions
def generate_small_rsa_keys():
    # Generate small RSA keys for simplicity
    p = 61
    q = 53
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 17
    d = modinv(e, phi)
    return (n, e), d

def modinv(a, m):
    # Compute the modular inverse of a modulo m
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1

def compute_small_hash(data):
    # Compute a simple hash function for the data
    return sum(bytearray(data.encode('utf-8'))) % 100

# Key generation
public_key, d = generate_small_rsa_keys()
n, e = public_key

# User identity hash computation
def compute_private_key_for_id(identity):
    H_ID = compute_small_hash(identity)
    DID = pow(H_ID, d, n)
    return DID

# Signing a message
def sign_message(identity, message):
    DID = compute_private_key_for_id(identity)
    H_M = compute_small_hash(message)
    sigma = (H_M * DID) % n
    return sigma

# Aggregation of signatures
def aggregate_signatures(signatures):
    sigma_agg = 1
    for sigma in signatures:
        sigma_agg = (sigma_agg * sigma) % n
    return sigma_agg

# Verification of aggregated signature
def verify_aggregate_signature(identities, messages, sigma_agg):
    P_agg = 1
    H_M_prod = 1
    for identity, message in zip(identities, messages):
        H_ID = compute_small_hash(identity)
        H_M = compute_small_hash(message)
        P_agg = (P_agg * H_ID) % n
        H_M_prod = (H_M_prod * H_M) % n
        print(f"Intermediate P_agg: {P_agg}, H_M_prod: {H_M_prod}")

    left = pow(sigma_agg, e, n)
    right = (H_M_prod * P_agg) % n

    print(f"Verification Debug:")
    print(f"P_agg: {P_agg}")
    print(f"H_M_prod: {H_M_prod}")
    print(f"left: {left}")
    print(f"right: {right}")

    return left == right

# Example usage
identities = ["user1", "user2"]
messages = ["message1", "message2"]

# Generate individual signatures
signatures = [sign_message(identity, message) for identity, message in zip(identities, messages)]

# Print intermediate values for debugging
for i, (identity, message, signature) in enumerate(zip(identities, messages, signatures)):
    H_ID = compute_small_hash(identity)
    DID = compute_private_key_for_id(identity)
    H_M = compute_small_hash(message)
    print(f"Identity {i+1}: {identity}")
    print(f"Message {i+1}: {message}")
    print(f"H_ID {i+1}: {H_ID}")
    print(f"DID {i+1}: {DID}")
    print(f"H_M {i+1}: {H_M}")
    print(f"Signature {i+1}: {signature}")

# Aggregate signatures
sigma_agg = aggregate_signatures(signatures)
print(f"Aggregated Signature: {sigma_agg}")

# Verify aggregated signature
is_valid = verify_aggregate_signature(identities, messages, sigma_agg)
print("Aggregated signature is valid:", is_valid)

# Additional checks
print(f"n: {n}")
print(f"e: {e}")
print(f"d: {d}")
for i, identity in enumerate(identities):
    H_ID = compute_small_hash(identity)
    DID = pow(H_ID, d, n)
    print(f"Identity {i+1}: {identity}, H_ID: {H_ID}, DID: {DID}")
for i, message in enumerate(messages):
    H_M = compute_small_hash(message)
    print(f"Message {i+1}: {message}, H_M: {H_M}")

# Manual check for left and right
left = pow(sigma_agg, e, n)
right = (1724 * 2846) % n
print(f"Manual left: {left}")
print(f"Manual right: {right}")

