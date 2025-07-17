# Dockerfile
FROM alpine:3.18
LABEL maintainer="devsecops@example.com"

# Install common OS packages, including python3 and pip for our automation
RUN apk update && \
    apk add --no-cache \
    curl \
    openssl \
    git \
    bash \
    python3 \
    py3-pip

# Example of a Python application setup that might have vulnerable dependencies
# Added by apply_fixes.py for Python packages

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["bash"]
