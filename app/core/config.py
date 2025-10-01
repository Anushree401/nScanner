"""Configuration constants for the scanner application."""

# Timeout settings (in seconds)
SOCKET_CONNECT_TIMEOUT = 3
SOCKET_RECV_TIMEOUT = 2
HTTP_REQUEST_TIMEOUT = 5
TLS_HANDSHAKE_TIMEOUT = 5
SMTP_TIMEOUT = 5

# Scanning limits
MAX_PORTS_PER_SCAN = 1000
MAX_CONCURRENT_SCANS = 5

# Port validation
MIN_PORT = 1
MAX_PORT = 65535

# Risk scoring thresholds
RISK_HIGH_THRESHOLD = 70
RISK_MEDIUM_THRESHOLD = 40

# Retry settings
HTTP_CHECK_RETRIES = 2

# Database
DEFAULT_DB_PATH = "sqlite:///./nscanner.db"