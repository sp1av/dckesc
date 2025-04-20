import pytest
from app.models import Scans, DockerScans, ImageScans

def test_create_scan(client, auth_headers):
    """Test creating a new scan."""
    response = client.post('/api/scan/create', 
        headers=auth_headers,
        data={
            'name': 'Test Scan',
            'description': 'Test Description'
        }
    )
    assert response.status_code == 200
    data = response.get_json()
    assert 'scan_id' in data

def test_get_scan(client, auth_headers):
    """Test retrieving a scan."""
    response = client.post('/api/scan/create', 
        headers=auth_headers,
        data={
            'name': 'Test Scan',
            'description': 'Test Description'
        }
    )
    scan_id = response.get_json()['scan_id']
    
    response = client.get(f'/api/scan/{scan_id}', headers=auth_headers)
    assert response.status_code == 200
    data = response.get_json()
    assert data['name'] == 'Test Scan'

def test_image_scan(client, auth_headers):
    """Test image scanning functionality."""
    response = client.post('/api/image-scan/create',
        headers=auth_headers,
        data={
            'registry': 'registry:5000',
            'tls_verify': 'no',
            'registry_name': 'test-registry',
            'image': 'test-image',
            'owner': 'testuser'
        }
    )
    assert response.status_code == 200
    data = response.get_json()
    assert 'scan_id' in data

def test_docker_scan(client, auth_headers):
    """Test Docker container scanning functionality."""
    response = client.post('/api/docker-scan/create',
        headers=auth_headers,
        data={
            'container_id': 'test-container',
            'scan_id': '1'
        }
    )
    assert response.status_code == 200
    data = response.get_json()
    assert 'scan_id' in data 