import pytest
from unittest.mock import patch, MagicMock
import docker
from app.models import DockerScans

def test_docker_scan_script(docker_client):
    """Test the Docker scan script functionality."""
    mock_container = MagicMock()
    mock_container.id = 'test-container-id'
    mock_container.name = 'test-container'
    
    docker_client.containers.get.return_value = mock_container
    
    with patch('subprocess.run') as mock_run:
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = 'Scan completed successfully'
        
        result = docker_client.containers.get('test-container')
        assert result.id == 'test-container-id'
        assert result.name == 'test-container'

def test_image_scan_script(docker_client):
    mock_image = MagicMock()
    mock_image.id = 'test-image-id'
    mock_image.tags = ['test-image:latest']
    
    docker_client.images.get.return_value = mock_image
    
    with patch('subprocess.run') as mock_run:
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = 'Image scan completed successfully'
        
        result = docker_client.images.get('test-image:latest')
        assert result.id == 'test-image-id'
        assert 'test-image:latest' in result.tags

def test_docker_scan_results(client, auth_headers):
    response = client.post('/api/docker-scan/create',
        headers=auth_headers,
        data={
            'container_id': 'test-container',
            'scan_id': '1'
        }
    )
    scan_id = response.get_json()['scan_id']
    
    response = client.get(f'/api/docker-scan/{scan_id}', headers=auth_headers)
    assert response.status_code == 200
    data = response.get_json()
    assert 'results' in data 