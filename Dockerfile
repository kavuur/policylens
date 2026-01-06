FROM python:3.11-slim

# System deps you already use (libpq for psycopg2, build tools for wheels)
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first for better layer caching
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy the app
COPY . /app

# Create an 'app' user with configurable IDs (matches docker-compose defaults)
ARG APP_UID=1000
ARG APP_GID=1000
RUN set -eux; \
    groupadd -g ${APP_GID} app || true; \
    useradd -u ${APP_UID} -g ${APP_GID} -m app || true; \
    chown -R ${APP_UID}:${APP_GID} /app

# We let docker-compose set the effective user; no USER here.
# USER app

EXPOSE 5000

# quiet some noisy libs (optional)
ENV TF_CPP_MIN_LOG_LEVEL=2 \
    TF_ENABLE_ONEDNN_OPTS=0

# Fallback default; compose's command overrides this while preserving 'app:app'
CMD ["gunicorn", "-w", "3", "-k", "gthread", "--threads", "2", "--timeout", "180", "-b", "0.0.0.0:5000", "app:app"]
