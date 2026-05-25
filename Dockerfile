FROM python:3.10-bullseye

# Install system dependencies required for Playwright, Frida, and wkhtmltopdf
RUN apt-get update && apt-get install -y \
    wget \
    gnupg \
    libglib2.0-0 \
    libnss3 \
    libx11-xcb1 \
    libxcomposite1 \
    libxcursor1 \
    libxdamage1 \
    libxi6 \
    libxtst6 \
    libnss3 \
    libcups2 \
    libxss1 \
    libxrandr2 \
    libasound2 \
    libpangocairo-1.0-0 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libgtk-3-0 \
    wkhtmltopdf \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install playwright browsers
RUN playwright install chromium

# Copy project files
COPY . .

# Create necessary directories
RUN mkdir -p logs reports sessions profiles tests

# Default command: run the web UI by default in the container
ENTRYPOINT ["python", "web_server.py"]
