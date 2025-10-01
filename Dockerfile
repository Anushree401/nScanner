# Dockerfile
# Base image with Python
FROM python:3.10-slim

# Install system dependencies
RUN apt-get update && apt-get install -y nmap && apt-get clean

# Set working directory
WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all source files
COPY . .

# Run the app (Fixed to run the FastAPI application using uvicorn)
# The entry point is app/main.py, running app.main:app on port 8000.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

# Expose port 8000 (Fixed to match the FastAPI port)
EXPOSE 8000