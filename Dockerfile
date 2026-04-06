FROM python:3.14-rc-slim  # Sử dụng RC version nếu có, hoặc build từ source

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libmagic1 \
    libyara-dev \
    git \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip và setuptools
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Copy requirements
COPY requirements.txt .

# Install Python dependencies (có thể cần --no-binary cho một số packages)
RUN pip install --no-cache-dir --prefer-binary -r requirements.txt || \
    pip install --no-cache-dir --no-binary :all: -r requirements.txt

# Copy application
COPY app/ ./app/

# Create upload directory
RUN mkdir -p /app/uploads

# Expose port
EXPOSE 8000

# Run application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]