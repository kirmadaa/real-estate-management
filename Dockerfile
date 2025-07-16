# Dockerfile
FROM alpine:3.19 # Updated base image to a newer patch/minor version
LABEL maintainer="devsecops@example.com"

# Example: Install some packages, potentially old versions
# RUN apk update && apk add --no-cache curl openssl git bash # Original line might be commented or removed if replaced by global upgrade

RUN apk upgrade --no-cache # Added by apply_fixes.py for OS package upgrades
RUN pip install --upgrade requests && pip install --upgrade urllib3 # Added by apply_fixes.py for Python packages

WORKDIR /app
COPY requirements.txt .
# RUN pip install --no-cache-dir -r requirements.txt # Original line might be left or modified based on strategy

COPY . .

CMD ["bash"]
