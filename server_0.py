import pandas as pd
from flask import Flask, jsonify, request
from BloomFilter import BloomFilter
from token_manager import TokenManager

app = Flask(__name__)

# Use Redis-backed TokenManager
token_manager = TokenManager()

# Load the dataset
dataset_path = "C:\\Users\\HEMANTH\\CLOUD_SERVER\\Secure-Local-Storage-with-Spatial-Query\\reduced_healthcare_dataset.csv"
try:
    data_store = pd.read_csv(dataset_path)
    print("Dataset loaded successfully.")
except FileNotFoundError:
    print(f"Dataset not found at {dataset_path}. Initializing with an empty DataFrame.")
    data_store = pd.DataFrame(columns=[
        "name", "age", "gender", "blood_type", "medical_condition",
        "date_of_admission", "doctor", "hospital", "insurance_provider",
        "billing_amount", "room_number", "admission_type",
        "discharge_date", "medication", "test_results", "latitude", "longitude"
    ])

# Initialize Bloom Filter
bloom_filter = BloomFilter()

# Add data from the dataset to the Bloom Filter
for index, row in data_store.iterrows():
    bloom_filter.add("Name", row["name"])


@app.route('/generate_token', methods=['POST'])
def generate_token():
    """Generate an access token for users."""
    user_id = request.json.get('user_id')
    if not user_id:
        return jsonify({"error": "Missing 'user_id'"}), 400
    token = token_manager.generate_access_token(user_id)
    print(f"Generated Token: {token}")
    return jsonify({"token": token}), 200


@app.route('/add_data', methods=['POST'])
def add_data():
    """Add data to the dataset and update the Bloom Filter."""
    token = request.headers.get("Authorization")
    if not token or not token_manager.validate_access_token(token):
        return jsonify({"error": "Unauthorized access"}), 401

    new_data = request.json
    if not new_data:
        return jsonify({"error": "Invalid or missing data"}), 400

    try:
        bloom_filter.add("Name", new_data["name"])
        global data_store
        new_row = pd.DataFrame([new_data])
        data_store = pd.concat([data_store, new_row], ignore_index=True)
        data_store.to_csv(dataset_path, index=False)
        return jsonify({"status": "Data added successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/view_data', methods=['GET'])
def view_data():
    """View the data from the dataset."""
    return jsonify(data_store.to_dict(orient="records")), 200


if __name__ == "__main__":
    app.run(port=5000, debug=True)