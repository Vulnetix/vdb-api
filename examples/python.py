#!/usr/bin/env python3
"""
VDB API Testing Console - AWS SigV4 Authentication Example
This script demonstrates how to authenticate with the VDB API using AWS SigV4
and make authenticated requests using botocore for request signing.
"""

import json
import requests
from datetime import datetime
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
import botocore.credentials

# Step 1: Set your Organization credentials
VVD_ORG = "f7c11fc1-d422-4242-a05e-ea3e747b07bc"  # Organization UUID (used as access key)
VVD_SECRET = "ldCTA9jeOLtHdkByhLl8DyIIo5bd2Meb6IA4rATn0KCanfzU2s97CTBQ7bxtYTIs"  # Organization Secret (64 chars)
VVD_ACCESS_KEY = VVD_ORG  # Access key is the Organization UUID

# AWS SigV4 Configuration
REGION = "us-east-1"
SERVICE = "vdb"

# API Base URL
BASE_URL = "https://api.vdb.vulnetix.com/v1"


# Step 2: Create SigV4 signing function
def sign_request(method, url, headers=None, body=None):
    """
    Sign an HTTP request using AWS SigV4 with botocore.
    
    Args:
        method: HTTP method (GET, POST, etc.)
        url: Full URL to sign
        headers: Optional headers dict
        body: Optional request body
    
    Returns:
        Dictionary of headers including Authorization header
    """
    # Create botocore credentials
    credentials = botocore.credentials.Credentials(
        access_key=VVD_ACCESS_KEY,
        secret_key=VVD_SECRET
    )
    
    # Create AWS request object
    request = AWSRequest(method=method, url=url, headers=headers, data=body)
    
    # Sign the request with SigV4
    SigV4Auth(credentials, SERVICE, REGION).add_auth(request)
    
    # Return signed headers
    return dict(request.headers)


# Step 3: Function to get JWT token using SigV4
def get_jwt_token():
    """
    Exchange SigV4-signed request for a JWT token.
    
    Returns:
        JWT token string
    """
    print("Requesting JWT token from /v1/auth/token...")
    
    # Build the URL
    url = f"{BASE_URL}/auth/token"
    
    # Sign the request
    signed_headers = sign_request("GET", url)
    
    # Make the request
    response = requests.get(url, headers=signed_headers)
    response.raise_for_status()
    
    # Parse response
    data = response.json()
    
    # Expected response format:
    # {
    #   "token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9...",
    #   "iss": "urn:vulnetix:vdb",
    #   "sub": "urn:uuid:12345678-1234-1234-1234-123456789abc",
    #   "exp": 1234567890
    # }
    
    token = data.get("token")
    print(f"JWT token obtained (expires in 15 minutes): {token[:50]}...")
    
    return token


# Step 4: Make authenticated API request
def make_api_request():
    """
    Make authenticated GET request to /ecosystems
    """
    # Get JWT token
    jwt_token = get_jwt_token()
    
    print("Making GET request to /ecosystems...")
    
    # Build the URL
    url = f"{BASE_URL}/ecosystems"
    
    # Set headers with JWT token
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Content-Type": "application/json"
    }
    
    # Make the request
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    
    # Parse and print response
    data = response.json()
    print(json.dumps(data, indent=2))
    
    return data


if __name__ == "__main__":
    try:
        make_api_request()
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        if hasattr(e, "response") and e.response is not None:
            print(f"Response: {e.response.text}")
