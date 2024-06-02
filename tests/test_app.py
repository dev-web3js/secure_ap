import pytest
from app import app

@pytest.fixture
def client():
    with app.test_client() as client:
        yield client

def test_user_registration(client):
    response = client.post('/register', json={"username": "testuser", "password": "testpass"})
    assert response.status_code == 201
    response_data = response.get_json()
    assert response_data["message"] == "User registered successfully"

def test_user_login(client):
    client.post('/register', json={"username": "testuser", "password": "testpass"})
    response = client.post('/login', json={"username": "testuser", "password": "testpass"})
    assert response.status_code == 200
    response_data = response.get_json()
    assert "access_token" in response_data

def test_user_2fa(client):
    client.post('/register', json={"username": "testuser", "password": "testpass"})
    client.post('/login', json={"username": "testuser", "password": "testpass"})
    response = client.post('/2fa', json={"username": "testuser", "2fa_code": "123456"})
    assert response.status_code == 200
    response_data = response.get_json()
    assert "message" in response_data

def test_create_user(client):
    response = client.post('/user', json={"name": "John", "age": 30, "occupation": "Engineer", "role": "customer"})
    assert response.status_code == 201
    response_data = response.get_json()
    assert response_data["name"] == "John"

def test_get_user(client):
    client.post('/user', json={"name": "John", "age": 30, "occupation": "Engineer", "role": "customer"})
    response = client.get('/user/John')
    assert response.status_code == 200
    response_data = response.get_json()
    assert response_data["name"] == "John"

def test_update_user(client):
    client.post('/user', json={"name": "John", "age": 30, "occupation": "Engineer", "role": "customer"})
    response = client.put('/user/John', json={"name": "John", "age": 31, "occupation": "Senior Engineer", "role": "customer"})
    assert response.status_code == 200
    response_data = response.get_json()
    assert response_data["age"] == 31

def test_delete_user(client):
    client.post('/user', json={"name": "John", "age": 30, "occupation": "Engineer", "role": "customer"})
    response = client.delete('/user/John')
    assert response.status_code == 200
    response_data = response.get_json()
    assert response_data["message"] == "User deleted"
