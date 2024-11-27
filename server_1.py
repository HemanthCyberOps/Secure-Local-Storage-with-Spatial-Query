import pandas as pd
from flask import Flask, request, jsonify
from paillier import public_key, private_key, EncryptedNumber, encrypt_data, decrypt_data, homomorphic_addition
from token_manager import TokenManager
import os

app = Flask(__name__)

# Use Redis-backed TokenManager
token_manager = TokenManager()

# Dataset path
dataset_path = "C:\\Users\\HEMANTH\\CLOUD_SERVER\\Secure-Local-Storage-with-Spatial-Query\\reduced_healthcare_dataset.csv"
if not os.path.exists(dataset_path):
    raise FileNotFoundError(f"Dataset not found at path: {dataset_path}")

# Load the dataset
data_store = pd.read_csv(dataset_path)

# Define a scaling factor for floating-point handling
SCALING_FACTOR = 10**15


def scale_float(value):
    """Scale a floating-point number to an integer."""
    return int(value * SCALING_FACTOR)


def descale_float(value):
    """Descale an integer to its original floating-point value."""
    return value / SCALING_FACTOR


@app.route('/generate_token', methods=['POST'])
def generate_token():
    """Generate an access token for users."""
    user_id = request.json.get('user_id')
    if not user_id:
        return jsonify({"error": "Missing 'user_id'"}), 400
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


@app.route('/knn_query', methods=['POST'])
def knn_query():
    """Perform a KNN query using latitude and longitude."""
    query_token = request.headers.get("Query-Token")
    access_token = request.headers.get("Authorization")
    if not token_manager.validate_query_token(access_token, query_token):
        return jsonify({"error": "Unauthorized access"}), 401

    try:
        global data_store
        data_store = pd.read_csv(dataset_path)
        query = request.json
        query_lat, query_lon, k = query["latitude"], query["longitude"], query["k"]
        data_store["distance"] = data_store.apply(
            lambda row: ((row["latitude"] - query_lat) ** 2 + (row["longitude"] - query_lon) ** 2) ** 0.5, axis=1
        )
        knn_results = data_store.nsmallest(k, "distance")[[
            "name", "age", "gender", "blood_type", "medical_condition",
            "doctor", "hospital", "insurance_provider", "distance"
        ]]
        return jsonify({"knn_results": knn_results.to_dict(orient="records")}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/view_encrypted', methods=['POST'])
def view_encrypted():
    """View encrypted data for a specific field and name."""
    try:
        token = request.headers.get("Authorization")
        if not token or not token_manager.validate_access_token(token):
            return jsonify({"error": "Unauthorized access"}), 401

        global data_store
        data_store = pd.read_csv(dataset_path)

        field = request.json.get("field")
        name = request.json.get("name")

        if not field or not name:
            return jsonify({"error": "Field and name must be provided."}), 400
        if field not in data_store.columns:
            return jsonify({"error": f"Field '{field}' not found in the dataset."}), 400

        filtered_data = data_store[data_store['name'] == name]
        if filtered_data.empty:
            return jsonify({"error": f"No records found for name '{name}'."}), 404

        encrypted_values = encrypt_data(filtered_data[field].tolist())
        encrypted_result = [str(enc_value.ciphertext()) for enc_value in encrypted_values]

        return jsonify({"encrypted_data": encrypted_result}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/homomorphic_add_two_names', methods=['POST'])
def homomorphic_add_two_names():
    """Perform homomorphic addition for billing_amount."""
    try:
        field = request.json.get('field')
        name1 = request.json.get('name1')
        name2 = request.json.get('name2')

        if not field or not name1 or not name2:
            return jsonify({"error": "Field, name1, and name2 must be provided."}), 400

        if field not in data_store.columns:
            return jsonify({"error": f"Field '{field}' not found in the dataset."}), 400

        # Filter dataset for the given names
        data_name1 = data_store[data_store['name'] == name1]
        data_name2 = data_store[data_store['name'] == name2]

        if data_name1.empty:
            return jsonify({"error": f"No records found for name '{name1}'."}), 404
        if data_name2.empty:
            return jsonify({"error": f"No records found for name '{name2}'."}), 404

        # Scale the floating-point values for encryption
        billing1 = scale_float(data_name1[field].iloc[0])
        billing2 = scale_float(data_name2[field].iloc[0])

        # Encrypt the values
        encrypted_value1 = public_key.encrypt(billing1)
        encrypted_value2 = public_key.encrypt(billing2)

        # Perform homomorphic addition
        encrypted_sum = encrypted_value1 + encrypted_value2

        return jsonify({
            "field": field,
            "name1": name1,
            "name2": name2,
            "encrypted_sum": str(encrypted_sum.ciphertext())
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/retrieve_homomorphic_plaintext', methods=['POST'])
def retrieve_homomorphic_plaintext():
    """Decrypt and retrieve plaintext for a homomorphic addition result."""
    try:
        encrypted_sum = request.json.get('encrypted_sum')
        if not encrypted_sum:
            return jsonify({"error": "Missing 'encrypted_sum'."}), 400

        # Decrypt the encrypted sum
        encrypted_number = EncryptedNumber(public_key, int(encrypted_sum))
        decrypted_scaled_value = private_key.decrypt(encrypted_number)

        # Descale the decrypted value to restore the original floating-point number
        original_value = descale_float(decrypted_scaled_value)

        return jsonify({"decrypted_value": original_value}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/retrieve_encrypted_plaintext', methods=['POST'])
def retrieve_encrypted_plaintext():
    """Decrypt and retrieve plaintext values for encrypted data."""
    try:
        encrypted_data = request.json.get('encrypted_data')
        if not encrypted_data or not isinstance(encrypted_data, list):
            return jsonify({"error": "Invalid or missing 'encrypted_data'. Expected a list."}), 400

        decrypted_values = [
            descale_float(private_key.decrypt(EncryptedNumber(public_key, int(ciphertext))))
            for ciphertext in encrypted_data
        ]

        return jsonify({"decrypted_values": decrypted_values}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(port=5001, debug=True)
