import pytest
from app import create_app, db
from app.models import User, Scans, DockerScans, ImageScans
import os
import tempfile
import docker

@pytest.fixture
def app():
    """Create and configure a new app instance for each test."""
    # Create a temporary file to isolate the database for each test
    db_fd, db_path = tempfile.mkstemp()
    
    app = create_app({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': f'sqlite:///{db_path}',
        'WTF_CSRF_ENABLED': False,
    })

    # Create the database and load test data
    with app.app_context():
        db.create_all()
        # Create test user
        test_user = User(username='testuser', password='testpass')
        db.session.add(test_user)
        db.session.commit()

    yield app

    # Clean up
    os.close(db_fd)
    os.unlink(db_path)

@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()

@pytest.fixture
def runner(app):
    """A test runner for the app's Click commands."""
    return app.test_cli_runner()

@pytest.fixture
def docker_client():
    """Docker client fixture."""
    return docker.from_env()

@pytest.fixture
def auth_headers(client):
    """Get authentication headers for API requests."""
    response = client.post('/login', data={
        'username': 'testuser',
        'password': 'testpass'
    })
    assert response.status_code == 302  # Redirect after successful login
    return {'Cookie': response.headers.get('Set-Cookie')} 