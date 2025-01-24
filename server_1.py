import pandas as pd
from flask import Flask, request, jsonify
from paillier import public_key, private_key, EncryptedNumber, encrypt_data, decrypt_data
from token_manager import TokenManager
from BloomFilter import BloomFilter
import os
from paillier import encrypt_data
import requests

app = Flask(__name__)

# Dataset path - Define this before referencing it!
dataset_path = "reduced_healthcare_dataset.csv"

# Check if the dataset exists
if not os.path.exists(dataset_path):
    raise FileNotFoundError(f"Dataset not found at path: {dataset_path}")

# Load the dataset
data_store = pd.read_csv(dataset_path)
print(f"Dataset loaded successfully. Records loaded: {len(data_store)}")

# Ensure billing_amount column has no NaN values
if "billing_amount" in data_store.columns:
    # Fill NaN values with 0 or another default value
    data_store["billing_amount"] = data_store["billing_amount"].fillna(0)
    data_store["billing_amount"] = pd.to_numeric(data_store["billing_amount"], errors='coerce').fillna(0)

    # Encrypt billing_amount and add it as a new column
    data_store["billing_amount_encrypted"] = encrypt_data(data_store["billing_amount"].tolist())
else:
    print("[ERROR] 'billing_amount' column is missing from the dataset.")

# Initialize Redis-backed TokenManager
token_manager = TokenManager()

# Initialize Bloom Filter
bloom_filter = BloomFilter()

# Add relevant fields to the Bloom Filter
for index, row in data_store.iterrows():
    for field in ["name", "age"]:
        bloom_filter.add(field, row[field])

@app.before_request
def require_authorization():
    """Require valid access tokens for all endpoints except token generation."""
    if request.endpoint not in ['generate_token', 'generate_query_token']:
        token = request.headers.get("Authorization")
        if not token or not token_manager.validate_access_token(token):
            return jsonify({"error": "Unauthorized access. Invalid token."}), 401

@app.route('/generate_token', methods=['POST'])
def generate_token():
    """Generate an access token for users."""
    user_id = request.json.get('user_id')
    if not user_id:
        return jsonify({"error": "Missing 'user_id'"}), 400
    token_manager.revoke_tokens_for_user(user_id)
    token = token_manager.generate_access_token(user_id)
    return jsonify({"token": token}), 200

@app.route('/generate_query_token', methods=['POST'])
def generate_query_token():
    """Generate a query-specific token."""
    access_token = request.headers.get("Authorization")
    if not token_manager.validate_access_token(access_token):
        return jsonify({"error": "Unauthorized access"}), 401
    query_token = token_manager.generate_query_token(access_token)
    return jsonify({"query_token": query_token}), 200

SERVER_2_URL = "http://127.0.0.1:5002"  # Update this with the actual Server 2 address

@app.route('/decrypt_sum', methods=['POST'])
def forward_decryption_to_server_2():
    """Forward the decryption request to Server 2."""
    try:
        encrypted_sum = request.json.get('encrypted_sum')

        if not encrypted_sum:
            return jsonify({"error": "Missing 'encrypted_sum'."}), 400

        # Forward the request to Server 2
        response = requests.post(f"{SERVER_2_URL}/decrypt_sum", json={"encrypted_sum": encrypted_sum})

        if response.status_code == 200:
            return response.json(), 200
        else:
            return jsonify({"error": "Decryption failed on Server 2.", "details": response.json()}), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route('/exact_match', methods=['POST'])
def exact_match_query():
    """Handle exact match queries with query token validation and customized result fields."""
    query_token = request.headers.get("Query-Token")
    access_token = request.headers.get("Authorization")

    # Validate the query token
    if not query_token or not token_manager.validate_query_token(access_token, query_token):
        return jsonify({"error": "Unauthorized access. Invalid or missing query token."}), 401

    try:
        # Ensure the request body is parsed as JSON
        request_data = request.get_json()
        if not request_data:
            return jsonify({"error": "Invalid or missing JSON body."}), 400

        field = request_data.get('field')
        value = request_data.get('value')

        # Validate input parameters
        if not field or value is None:
            return jsonify({"error": "Field and value must be provided."}), 400

        # Check existence in the Bloom Filter
        if not bloom_filter.lookup(field, value):
            return jsonify({"error": f"Value not found in dataset for {field} = {value}."}), 404

        # Query the dataset for an exact match
        matched_data = data_store[data_store[field] == value]
        if matched_data.empty:
            return jsonify({"error": f"No records found for {field} = {value}."}), 404

        # Prepare the result with specific fields: "name", "hospital", "medical_condition", "insurance_provider"
        results = []
        for _, row in matched_data.iterrows():
            result = {
                "name": row["name"],  # Include the name
                "hospital": row["hospital"],  # Include the hospital
                "medical_condition": row["medical_condition"],  # Include the medical condition
                "insurance_provider": row["insurance_provider"]  # Include the insurance provider
            }
            results.append(result)

        return jsonify({"results": results}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/range_query', methods=['POST'])
def range_query():
    """Handle range queries with query token validation and customized result fields."""
    query_token = request.headers.get("Query-Token")
    access_token = request.headers.get("Authorization")

    # Validate the query token
    if not query_token or not token_manager.validate_query_token(access_token, query_token):
        return jsonify({"error": "Unauthorized access. Invalid or missing query token."}), 401

    try:
        # Ensure the request body is parsed as JSON
        request_data = request.get_json()
        if not request_data:
            return jsonify({"error": "Invalid or missing JSON body."}), 400

        field = request_data.get('field')
        min_value = request_data.get('min_value')
        max_value = request_data.get('max_value')

        # Validate input parameters
        if not field or min_value is None or max_value is None:
            return jsonify({"error": "Field, min_value, and max_value must be provided."}), 400

        # Ensure the field exists and is numeric
        if field not in data_store.columns:
            return jsonify({"error": f"Field '{field}' not found in the dataset."}), 400
        if data_store[field].dtype not in ['int64', 'float64']:
            return jsonify({"error": f"Field '{field}' must be numeric for range queries."}), 400

        # Filter the dataset based on the range
        range_data = data_store[(data_store[field] >= min_value) & (data_store[field] <= max_value)]
        if range_data.empty:
            return jsonify({"error": "No records found within the specified range."}), 404

        # Prepare the result with specific fields: "name", "hospital", "medical_condition", "insurance_provider"
        results = []
        for _, row in range_data.iterrows():
            result = {
                "name": row["name"],  # Include the name
                "hospital": row["hospital"],  # Include the hospital
                "medical_condition": row["medical_condition"],  # Include the medical condition
                "insurance_provider": row["insurance_provider"]  # Include the insurance provider
            }
            results.append(result)

        return jsonify({"results": results}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/knn_query', methods=['POST'])
def knn_query():
    """Perform a KNN query using latitude and longitude with proper token validation."""
    query_token = request.headers.get("Query-Token")
    access_token = request.headers.get("Authorization")

    # Debug token validation
    print(f"[DEBUG] Authorization Token: {access_token}")
    print(f"[DEBUG] Query Token: {query_token}")

    # Validate the query token
    if not query_token or not token_manager.validate_query_token(access_token, query_token):
        print("[DEBUG] Token validation failed.")
        return jsonify({"error": "Unauthorized access. Invalid or missing query token."}), 401

    print("[DEBUG] Token validation passed.")
    try:
        # Ensure the request body is parsed as JSON
        request_data = request.get_json()
        if not request_data:
            return jsonify({"error": "Invalid or missing JSON body."}), 400

        query_lat = request_data.get("latitude")
        query_lon = request_data.get("longitude")
        k = request_data.get("k")

        # Validate input parameters
        if query_lat is None or query_lon is None or k is None:
            return jsonify({"error": "Latitude, longitude, and k must be provided."}), 400

        # Ensure k is a positive integer
        if not isinstance(k, int) or k <= 0:
            return jsonify({"error": "'k' must be a positive integer."}), 400

        # Compute distances and sort by nearest neighbors
        data_store["distance"] = data_store.apply(
            lambda row: ((row["latitude"] - query_lat) ** 2 + (row["longitude"] - query_lon) ** 2) ** 0.5, axis=1
        )
        knn_results = data_store.nsmallest(k, "distance")[[
            "name", "hospital", "medical_condition", "insurance_provider", "distance"
        ]]

        # Prepare the result
        results = knn_results.to_dict(orient="records")
        return jsonify({"knn_results": results}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(port=5001, debug=True)
