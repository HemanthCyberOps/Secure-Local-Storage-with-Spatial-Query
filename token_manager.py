
import redis
import secrets

class TokenManager:
    def __init__(self):
        # Connect to Redis
        self.redis_client = redis.StrictRedis(
            host='127.0.0.1',  # Redis server address
            port=6379,         # Redis server port
            db=0,              # Redis database (default is 0)
            decode_responses=True  # Ensures the data is stored as strings
        )

    def generate_access_token(self, user_id):
        """Generate and store a secure access token for a user."""
        token = secrets.token_hex(16)
        self.redis_client.set(token, user_id, ex=3600)  # Token with 1-hour expiration
        return token

    def validate_access_token(self, token):
        """Validate if an access token exists in the Redis store."""
        return self.redis_client.exists(token)

    def generate_query_token(self, access_token):
        """Generate a query token for an authorized access token."""
        if not self.validate_access_token(access_token):
            raise ValueError("Invalid access token")
        query_token = secrets.token_hex(16)
        self.redis_client.set(query_token, access_token, ex=3600)  # Query token with 1-hour expiration
        return query_token

    def validate_query_token(self, access_token, query_token):
        """Validate if a query token is associated with the provided access token."""
        stored_access_token = self.redis_client.get(query_token)
        return stored_access_token == access_token
