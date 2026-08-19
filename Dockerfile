FROM node:20-bookworm-slim

# Install system dependencies, nmap, python3, pip, git, and core tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    git \
    curl \
    wget \
    python3 \
    python3-pip \
    python3-venv \
    build-essential \
    ca-certificates \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Install Python AppSec tools: Bandit, pip-audit, Semgrep
RUN pip3 install --no-cache-dir --break-system-packages bandit pip-audit semgrep

# Install Gitleaks for secret detection
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then G_ARCH="x64"; else G_ARCH="arm64"; fi && \
    wget -q https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_${G_ARCH}.tar.gz -O /tmp/gitleaks.tar.gz && \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin/ gitleaks && \
    rm /tmp/gitleaks.tar.gz && \
    chmod +x /usr/local/bin/gitleaks

# Install Trivy for container & config security analysis
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

WORKDIR /app

# Install Node dependencies
COPY package*.json ./
RUN npm ci || npm install

# Copy application source code
COPY . .

# Build frontend and server bundle
RUN npm run build

EXPOSE 3000

ENV PORT=3000
ENV NODE_ENV=production

CMD ["npm", "start"]
