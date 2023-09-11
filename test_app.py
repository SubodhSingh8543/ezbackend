import pytest
from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

# Define test cases for the routes
def test_download_pdf(client):
    response = client.get('/download_pdf/64fed94a2628e7f9bfdc3cec')
    assert response.status_code == 200
    assert response.headers['Content-Disposition'] == 'attachment; filename="xyz.pdf"'

def test_upload_file(client):
    # Simulate a file upload
    with open('test.pdf', 'rb') as pdf_file:
        data = {'file': (pdf_file, 'test.pdf')}
        response = client.post('/upload', data=data, content_type='multipart/form-data')
    assert response.status_code == 200
    assert 'File uploaded successfully' in response.get_json().get('message')

def test_add_user(client):
    user_data = {'email': 'testuser@example.com', 'password': 'password'}
    response = client.post('/users', json=user_data)
    assert response.status_code == 200
    assert 'id' in response.get_json()

def test_login(client):
    login_data = {'email': 'testuser@example.com', 'password': 'password'}
    response = client.post('/login', json=login_data)
    assert response.status_code == 200
    assert 'access_token' in response.get_json()

def test_add_clinteuser(client):
    clinteuser_data = {'email': 'testclinteuser@example.com', 'password': 'password'}
    response = client.post('/clintesignup', json=clinteuser_data)
    assert response.status_code == 200
    assert 'id' in response.get_json()

def test_clintelogin(client):
    login_data = {'email': 'testclinteuser@example.com', 'password': 'password'}
    response = client.post('/clintelogin', json=login_data)
    assert response.status_code == 200
    assert 'access_token' in response.get_json()

def test_get_pdf_data(client):
    response = client.get('/get_pdf_data')
    assert response.status_code == 200
    assert isinstance(response.get_json(), list)

# Add more test cases for other routes as needed

if __name__ == '__main__':
    pytest.main()
