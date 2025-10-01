# tests/test_api.py
"""Basic tests for the FastAPI application."""

import pytest
from fastapi.testclient import TestClient
from app.api.routes import app

client = TestClient(app)


class TestHealthEndpoint:
    """Test health check endpoint."""
    
    def test_health_check(self):
        """Test that health endpoint returns OK."""
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"


class TestScanEndpoints:
    """Test scan-related endpoints."""
    
    def test_create_scan(self):
        """Test creating a new scan."""
        response = client.post(
            "/api/scan",
            json={"host": "scanme.nmap.org", "ports": "80"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "scan_id" in data
        assert data["status"] == "queued"
    
    def test_create_scan_invalid_host(self):
        """Test creating scan with invalid host."""
        response = client.post(
            "/api/scan",
            json={"host": "", "ports": "80"}
        )
        assert response.status_code == 422  # Validation error
    
    def test_create_scan_invalid_ports(self):
        """Test creating scan with invalid ports."""
        response = client.post(
            "/api/scan",
            json={"host": "scanme.nmap.org", "ports": ""}
        )
        assert response.status_code == 422  # Validation error
    
    def test_create_scan_too_many_ports(self):
        """Test creating scan with too many ports."""
        response = client.post(
            "/api/scan",
            json={"host": "scanme.nmap.org", "ports": "1-2000"}
        )
        assert response.status_code == 422  # Validation error
    
    def test_get_nonexistent_scan(self):
        """Test retrieving non-existent scan."""
        response = client.get("/api/scan/nonexistent-scan-id")
        assert response.status_code == 404
    
    def test_list_scans(self):
        """Test listing scans."""
        response = client.get("/api/scans")
        assert response.status_code == 200
        assert isinstance(response.json(), list)
    
    def test_list_scans_with_pagination(self):
        """Test listing scans with pagination."""
        response = client.get("/api/scans?limit=10&offset=0")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) <= 10
    
    def test_delete_nonexistent_scan(self):
        """Test deleting non-existent scan."""
        response = client.delete("/api/scan/nonexistent-scan-id")
        assert response.status_code == 404


class TestSchemaValidation:
    """Test API schema validation."""
    
    def test_scan_request_missing_host(self):
        """Test scan request with missing host."""
        response = client.post(
            "/api/scan",
            json={"ports": "80"}
        )
        assert response.status_code == 422
    
    def test_scan_request_default_ports(self):
        """Test that default ports are used when not specified."""
        response = client.post(
            "/api/scan",
            json={"host": "scanme.nmap.org"}
        )
        assert response.status_code == 200
    
    def test_localhost_scanning(self):
        """Test that localhost scanning is allowed."""
        response = client.post(
            "/api/scan",
            json={"host": "127.0.0.1", "ports": "80"}
        )
        # Should succeed (validation passes)
        assert response.status_code == 200


if __name__ == "__main__":
    pytest.main([__file__, "-v"])