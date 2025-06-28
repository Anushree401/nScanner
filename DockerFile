# Use a lightweight Python base image, base image is important for Render to detect it's a web service
FROM python:3.10-slim

# Install nmap and dependencies
RUN apt-get update && apt-get install -y nmap

# Set working directory
WORKDIR /app 

# Copy all project files to the image
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose port (important for Render to detect it's a web service)
EXPOSE 10000

# Start the Flask app
CMD ["python", "app.py"]
