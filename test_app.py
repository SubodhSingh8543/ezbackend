import json
import pytest
from app import app  # Import your Flask app from your main application file

@pytest.fixture
def client():
    # Create a test client
    app.config['TESTING'] = True
    client = app.test_client()

    yield client

def test_add_user(client):
    # Test adding a user
    user_data = {
        "email": "test@example.com",
        "password": "test_password"
    }
    response = client.post('/users', json=user_data)
    data = json.loads(response.data.decode('utf-8'))

    assert response.status_code == 200
    assert 'id' in data

def test_login_valid_credentials(client):
    # Test login with valid credentials
    user_data = {
        "email": "test@example.com",
        "password": "test_password"
    }
    client.post('/users', json=user_data)  # Create a user
    response = client.post('/login', json=user_data)
    data = json.loads(response.data.decode('utf-8'))

    assert response.status_code == 200
    assert 'access_token' in data

def test_login_invalid_credentials(client):
    # Test login with invalid credentials
    user_data = {
        "email": "test@example.com",
        "password": "test_password"
    }
    client.post('/users', json=user_data)  # Create a user
    invalid_data = {
        "email": "test@example.com",
        "password": "wrong_password"
    }
    response = client.post('/login', json=invalid_data)
    data = json.loads(response.data.decode('utf-8'))

    assert response.status_code == 401
    assert 'message' in data
    assert data['message'] == 'Invalid username or password'
