#!/usr/bin/env bash
# ==============================================================================
# AI Application Security Auditor & Remediation Platform - Linux Setup Script
# Installs required AppSec, SAST, SCA, Secrets, and DAST tools on Linux
# Supported OS: Ubuntu, Debian, Kali Linux, Fedora, Arch, Alpine
# ==============================================================================

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}====================================================================${NC}"
echo -e "${GREEN}  AI Application Security Auditor & Remediation Platform - Installer ${NC}"
echo -e "${BLUE}====================================================================${NC}"

if [ "$EUID" -ne 0 ]; then
  echo -e "${YELLOW}[!] Warning: Running without sudo/root. Will use sudo for package installation.${NC}"
  SUDO="sudo"
else
  SUDO=""
fi

# Detect Linux Distribution
if [ -f /etc/os-release ]; then
  . /etc/os-release
  DISTRO=$ID
else
  DISTRO="unknown"
fi

echo -e "${BLUE}[*] Detected Linux OS: ${DISTRO}${NC}"

# 1. Base System Packages & Nmap
echo -e "\n${BLUE}[1/6] Installing Core Utilities & Nmap...${NC}"
if [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ] || [ "$DISTRO" = "kali" ]; then
  $SUDO apt-get update -y
  $SUDO apt-get install -y nmap curl wget git python3 python3-pip python3-venv build-essential jq
elif [ "$DISTRO" = "fedora" ] || [ "$DISTRO" = "rhel" ] || [ "$DISTRO" = "centos" ]; then
  $SUDO dnf install -y nmap curl wget git python3 python3-pip gcc jq
elif [ "$DISTRO" = "arch" ] || [ "$DISTRO" = "manjaro" ]; then
  $SUDO pacman -Sy --noconfirm nmap curl wget git python python-pip gcc jq
elif [ "$DISTRO" = "alpine" ]; then
  $SUDO apk add --no-cache nmap curl wget git python3 py3-pip gcc musl-dev jq nodejs npm
fi

# 2. Python Security Tools: Bandit, pip-audit, semgrep
echo -e "\n${BLUE}[2/6] Installing Python AppSec Analyzers (Bandit, pip-audit, Semgrep)...${NC}"
pip3 install --upgrade pip --break-system-packages 2>/dev/null || pip3 install --upgrade pip || true
pip3 install bandit pip-audit semgrep --break-system-packages 2>/dev/null || pip3 install bandit pip-audit semgrep || true

# 3. Gitleaks (Secret Scanner)
echo -e "\n${BLUE}[3/6] Installing Gitleaks for Automated Secret Detection...${NC}"
if ! command -v gitleaks &> /dev/null; then
  GITLEAKS_VER="8.18.4"
  ARCH=$(uname -m)
  case $ARCH in
    x86_64) G_ARCH="x64" ;;
    aarch64|arm64) G_ARCH="arm64" ;;
    *) G_ARCH="x64" ;;
  esac
  
  wget -q "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VER}/gitleaks_${GITLEAKS_VER}_linux_${G_ARCH}.tar.gz" -O /tmp/gitleaks.tar.gz
  tar -xzf /tmp/gitleaks.tar.gz -C /tmp/
  $SUDO mv /tmp/gitleaks /usr/local/bin/
  rm -f /tmp/gitleaks.tar.gz
  chmod +x /usr/local/bin/gitleaks
  echo -e "${GREEN}[✓] Gitleaks installed successfully.${NC}"
else
  echo -e "${GREEN}[✓] Gitleaks already installed: $(gitleaks version)${NC}"
fi

# 4. Trivy (Vulnerability & Container/Config Scanner)
echo -e "\n${BLUE}[4/6] Installing Trivy for Container & Config Scanning...${NC}"
if ! command -v trivy &> /dev/null; then
  if [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ] || [ "$DISTRO" = "kali" ]; then
    $SUDO apt-get install -y wget apt-transport-https gnupg lsb-release
    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | $SUDO gpg --dearmor -o /usr/share/keyrings/trivy.gpg --yes 2>/dev/null || true
    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | $SUDO tee -a /etc/apt/sources.list.d/trivy.list
    $SUDO apt-get update -y && $SUDO apt-get install -y trivy || true
  else
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | $SUDO sh -s -- -b /usr/local/bin
  fi
  echo -e "${GREEN}[✓] Trivy setup finished.${NC}"
else
  echo -e "${GREEN}[✓] Trivy already installed: $(trivy --version | head -n 1)${NC}"
fi

# 5. Node.js Environment & Dependencies
echo -e "\n${BLUE}[5/6] Checking Node.js and Installing Platform Packages...${NC}"
if ! command -v node &> /dev/null; then
  echo -e "${YELLOW}[!] Node.js not found. Installing Node.js LTS...${NC}"
  curl -fsSL https://deb.nodesource.com/setup_20.x | $SUDO bash -
  $SUDO apt-get install -y nodejs
fi

echo -e "${GREEN}[✓] Node version: $(node -v)${NC}"
echo -e "${GREEN}[✓] NPM version: $(npm -v)${NC}"

npm install

# 6. Verify Tool Availability
echo -e "\n${BLUE}[6/6] Summary of Installed Security Engine Tools:${NC}"
echo "--------------------------------------------------------"
printf "%-15s %-12s %-30s\n" "TOOL" "STATUS" "PATH"
echo "--------------------------------------------------------"

for tool in nmap gitleaks semgrep bandit pip-audit trivy git node npm; do
  if command -v $tool &> /dev/null; then
    printf "${GREEN}%-15s %-12s %-30s${NC}\n" "$tool" "INSTALLED" "$(which $tool)"
  else
    printf "${RED}%-15s %-12s %-30s${NC}\n" "$tool" "MISSING" "-"
  fi
done
echo "--------------------------------------------------------"

echo -e "\n${GREEN}✓ All setup complete!${NC}"
echo -e "Start the platform using: ${YELLOW}npm run dev${NC} or ${YELLOW}npm start${NC}"
