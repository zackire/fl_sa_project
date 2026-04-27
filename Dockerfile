FROM python:3.10-slim

# Don't write .pyc files; flush stdout/stderr immediately
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Upgrade pip first, then install deps using pre-built wheels where available.
# --prefer-binary avoids compiling C extensions from source (critical on ARM/RPi).
COPY requirements.txt .
RUN pip install --upgrade pip --quiet && \
    pip install --no-cache-dir --prefer-binary -r requirements.txt

COPY . .
