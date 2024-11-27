from flask import Flask, request, jsonify
from paillier import public_key, private_key, EncryptedNumber

app = Flask(__name__)

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        encrypted_data = request.json.get('encrypted_data')
        if not encrypted_data or not isinstance(encrypted_data, list):
            return jsonify({"error": "Invalid or missing 'encrypted_data'."}), 400

        decrypted_values = [
            private_key.decrypt(EncryptedNumber(public_key, int(ciphertext)))
            for ciphertext in encrypted_data
        ]
        return jsonify({"decrypted_values": decrypted_values}), 200
    except Exception as e:
        print(f"Error during decryption: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(port=5002, debug=True)