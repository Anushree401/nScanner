# tests/test_scanner.py
"""Basic tests for the scanner core functionality."""

import pytest
from app.core.scanner import validate_port, parse_port_spec, scanning
from app.core.risk import severity_weight, compute_port_score, summarize_scan


class TestPortValidation:
    """Test port validation logic."""
    
    def test_valid_ports(self):
        """Test that valid ports are accepted."""
        assert validate_port(80) is True
        assert validate_port(443) is True
        assert validate_port(1) is True
        assert validate_port(65535) is True
    
    def test_invalid_ports(self):
        """Test that invalid ports are rejected."""
        assert validate_port(0) is False
        assert validate_port(65536) is False
        assert validate_port(-1) is False
        assert validate_port("invalid") is False


class TestPortSpecParsing:
    """Test port specification parsing."""
    
    def test_single_port(self):
        """Test parsing single port."""
        result = parse_port_spec("80")
        assert result == [80]
    
    def test_comma_separated(self):
        """Test parsing comma-separated ports."""
        result = parse_port_spec("22,80,443")
        assert result == [22, 80, 443]
    
    def test_port_range(self):
        """Test parsing port range."""
        result = parse_port_spec("80-82")
        assert result == [80, 81, 82]
    
    def test_mixed_format(self):
        """Test parsing mixed format."""
        result = parse_port_spec("22,80-82,443")
        assert result == [22, 80, 81, 82, 443]
    
    def test_duplicates_removed(self):
        """Test that duplicates are removed."""
        result = parse_port_spec("80,80,80")
        assert result == [80]
    
    def test_invalid_format(self):
        """Test that invalid formats raise ValueError."""
        with pytest.raises(ValueError):
            parse_port_spec("invalid")
        
        with pytest.raises(ValueError):
            parse_port_spec("80-")
        
        with pytest.raises(ValueError):
            parse_port_spec("100-50")  # Invalid range


class TestRiskScoring:
    """Test risk scoring logic."""
    
    def test_severity_weights(self):
        """Test severity weight mapping."""
        assert severity_weight("critical") == 50
        assert severity_weight("high") == 30
        assert severity_weight("medium") == 15
        assert severity_weight("low") == 5
        assert severity_weight("info") == 0
    
    def test_closed_port_score(self):
        """Test that closed ports have zero score."""
        entry = {"state": "closed", "port": 80}
        assert compute_port_score(entry) == 0
    
    def test_open_port_base_score(self):
        """Test base score for open port."""
        entry = {"state": "open", "port": 8080, "findings": []}
        score = compute_port_score(entry)
        assert score >= 10  # At least base score
    
    def test_risky_port_bonus(self):
        """Test that risky ports get additional score."""
        normal_entry = {"state": "open", "port": 8080, "findings": []}
        risky_entry = {"state": "open", "port": 3389, "findings": []}  # RDP
        
        normal_score = compute_port_score(normal_entry)
        risky_score = compute_port_score(risky_entry)
        
        assert risky_score > normal_score


class TestScanSummary:
    """Test scan summarization."""
    
    def test_empty_results(self):
        """Test summarizing empty results."""
        summary = summarize_scan([])
        assert summary["open_ports"] == 0
        assert summary["closed_ports"] == 0
        assert summary["risk_score"] == 0
    
    def test_basic_summary(self):
        """Test basic scan summary."""
        results = [
            {"state": "open", "port": 80, "findings": []},
            {"state": "closed", "port": 81},
            {"error": "timeout", "port": 82}
        ]
        
        summary = summarize_scan(results)
        assert summary["open_ports"] == 1
        assert summary["closed_ports"] == 1
        assert summary["error_count"] == 1
    
    def test_risk_level_assignment(self):
        """Test risk level assignment."""
        # Low risk
        low_risk = [{"state": "open", "port": 8080, "findings": []}]
        summary = summarize_scan(low_risk)
        assert summary["risk_level"] in ["LOW", "MEDIUM"]
        
        # High risk with critical finding
        high_risk = [{
            "state": "open",
            "port": 3389,
            "findings": [{"severity": "critical", "type": "test"}]
        }]
        summary = summarize_scan(high_risk)
        assert summary["risk_level"] == "HIGH"


class TestScanning:
    """Test actual scanning functionality (using localhost)."""
    
    def test_invalid_host(self):
        """Test scanning invalid host."""
        results = scanning("invalid.host.that.does.not.exist.local", "80")
        assert len(results) > 0
        # Should have error entries
        assert any("error" in r for r in results)
    
    def test_invalid_port_spec(self):
        """Test invalid port specification."""
        results = scanning("localhost", "invalid")
        assert len(results) > 0
        assert "error" in results[0]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])