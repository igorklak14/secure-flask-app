# syntax=docker/dockerfile:1
FROM python:3.13-slim

# ---- Environment  ----
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONIOENCODING=UTF-8

# ---- System preparation ----

RUN useradd -m -u 10001 appuser


#     build-essential gcc libpq-dev \
#   && rm -rf /var/lib/apt/lists/*

# ---- Workdir ----
WORKDIR /app

# ---- Install Python deps  ----
COPY requirements.txt /app/
RUN python -m pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ---- Copy project ----
COPY . /app/


RUN mkdir -p /app/instance && chown -R appuser:appuser /app

# ---- Switch to non-root ----
USER appuser

# ---- Expose Flask port ----
EXPOSE 5000


CMD ["python", "run.py"]
