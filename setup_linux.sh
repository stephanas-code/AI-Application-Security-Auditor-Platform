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
  echo -e "${YELLOW}[!] Warning: Running without sudo/root. Will use sudo for system package installation.${NC}"
  SUDO="sudo"
else
  SUDO=""
fi

# Clean up any broken apt repository entries from previous runs
$SUDO rm -f /etc/apt/sources.list.d/trivy.list 2>/dev/null || true

# Detect Linux Distribution
if [ -f /etc/os-release ]; then
  . /etc/os-release
  DISTRO=$ID
else
  DISTRO="unknown"
fi

echo -e "${BLUE}[*] Detected Linux OS: ${DISTRO}${NC}"

# 1. Base System Packages & Nmap
echo -e "\n${BLUE}[1/6] Installing Core Utilities, Nmap & Node/NPM...${NC}"
if [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ] || [ "$DISTRO" = "kali" ]; then
  $SUDO apt-get update -y
  $SUDO apt-get install -y nmap curl wget git python3 python3-pip python3-venv build-essential jq nodejs npm
elif [ "$DISTRO" = "fedora" ] || [ "$DISTRO" = "rhel" ] || [ "$DISTRO" = "centos" ]; then
  $SUDO dnf install -y nmap curl wget git python3 python3-pip gcc jq nodejs npm
elif [ "$DISTRO" = "arch" ] || [ "$DISTRO" = "manjaro" ]; then
  $SUDO pacman -Sy --noconfirm nmap curl wget git python python-pip gcc jq nodejs npm
elif [ "$DISTRO" = "alpine" ]; then
  $SUDO apk add --no-cache nmap curl wget git python3 py3-pip gcc musl-dev jq nodejs npm
fi

# 2. Python Security Virtual Environment & AppSec Tools (venv)
echo -e "\n${BLUE}[2/6] Setting up Dedicated Python Virtual Environment for Linux...${NC}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if local venv has Linux bin/pip (not Windows Scripts/pip.exe)
if [ -f "$SCRIPT_DIR/venv/bin/pip" ]; then
  VENV_DIR="$SCRIPT_DIR/venv"
elif [ -f "$SCRIPT_DIR/.venv/bin/pip" ]; then
  VENV_DIR="$SCRIPT_DIR/.venv"
else
  # In VirtualBox/VMware shared folders, use Linux filesystem to avoid symlink/NTFS collisions
  VENV_DIR="$HOME/.appsec_venv"
  if [ ! -d "$VENV_DIR" ]; then
    echo -e "[*] Creating Linux-native virtual environment at $VENV_DIR..."
    python3 -m venv "$VENV_DIR"
  fi
fi

if [ ! -f "$VENV_DIR/bin/pip" ]; then
  echo -e "[*] Initializing virtual environment at $VENV_DIR..."
  python3 -m venv "$VENV_DIR"
fi

echo -e "[*] Installing Python AppSec dependencies from requirements.txt into $VENV_DIR..."
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install -r "$SCRIPT_DIR/requirements.txt"

# Link binaries to /usr/local/bin for system-wide access by server process
for tool in bandit pip-audit semgrep; do
  if [ -f "$VENV_DIR/bin/$tool" ]; then
    $SUDO ln -sf "$VENV_DIR/bin/$tool" "/usr/local/bin/$tool" 2>/dev/null || true
    $SUDO cp -f "$VENV_DIR/bin/$tool" "/usr/local/bin/$tool" 2>/dev/null || true
  fi
done
echo -e "${GREEN}[✓] Python security virtual environment configured successfully at: $VENV_DIR${NC}"

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
  $SUDO chmod +x /usr/local/bin/gitleaks
  echo -e "${GREEN}[✓] Gitleaks installed successfully.${NC}"
else
  echo -e "${GREEN}[✓] Gitleaks already installed: $(gitleaks version 2>/dev/null || echo 'ready')${NC}"
fi

# 4. Trivy (Container & Config Scanner)
echo -e "\n${BLUE}[4/6] Installing Trivy for Container & Config Scanning...${NC}"
if ! command -v trivy &> /dev/null; then
  TRIVY_VER="0.58.2"
  ARCH=$(uname -m)
  case $ARCH in
    x86_64) T_ARCH="64bit" ;;
    aarch64|arm64) T_ARCH="ARM64" ;;
    *) T_ARCH="64bit" ;;
  esac

  echo -e "[*] Downloading Trivy binary (Linux-${T_ARCH})..."
  if curl -sSL --connect-timeout 10 -o /tmp/trivy.tar.gz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VER}/trivy_${TRIVY_VER}_Linux-${T_ARCH}.tar.gz" 2>/dev/null; then
    tar -xzf /tmp/trivy.tar.gz -C /tmp/ trivy 2>/dev/null || tar -xzf /tmp/trivy.tar.gz -C /tmp/
    $SUDO mv /tmp/trivy /usr/local/bin/ 2>/dev/null || true
    rm -f /tmp/trivy.tar.gz
    $SUDO chmod +x /usr/local/bin/trivy 2>/dev/null || true
  fi

  # Fallback to official script if direct download failed
  if ! command -v trivy &> /dev/null; then
    echo -e "[*] Trying official Trivy install script fallback..."
    curl -sfL --connect-timeout 10 https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | $SUDO sh -s -- -b /usr/local/bin 2>/dev/null || true
  fi

  if command -v trivy &> /dev/null; then
    echo -e "${GREEN}[✓] Trivy installed successfully.${NC}"
  else
    echo -e "${YELLOW}[!] Trivy installation skipped (network timeout). You can install it later with: sudo apt install trivy${NC}"
  fi
else
  echo -e "${GREEN}[✓] Trivy already installed: $(trivy --version 2>/dev/null | head -n 1 || echo 'ready')${NC}"
fi

# 5. Node.js Environment & Dependencies
echo -e "\n${BLUE}[5/6] Checking Node.js and Installing Platform Packages...${NC}"
echo -e "${GREEN}[✓] Node version: $(node -v 2>/dev/null || echo 'N/A')${NC}"
echo -e "${GREEN}[✓] NPM version: $(npm -v 2>/dev/null || echo 'N/A')${NC}"

npm install

# 6. Verify Tool Availability
echo -e "\n${BLUE}[6/6] Summary of Installed Security Engine Tools:${NC}"
echo "--------------------------------------------------------"
printf "%-15s %-12s %-30s\n" "TOOL" "STATUS" "PATH"
echo "--------------------------------------------------------"

for tool in nmap gitleaks semgrep bandit pip-audit trivy git node npm; do
  if command -v $tool &> /dev/null; then
    printf "${GREEN}%-15s %-12s %-30s${NC}\n" "$tool" "INSTALLED" "$(which $tool)"
  elif [ -f "$VENV_DIR/bin/$tool" ]; then
    printf "${GREEN}%-15s %-12s %-30s${NC}\n" "$tool" "INSTALLED" "$VENV_DIR/bin/$tool"
  else
    printf "${YELLOW}%-15s %-12s %-30s${NC}\n" "$tool" "MISSING" "-"
  fi
done
echo "--------------------------------------------------------"

echo -e "\n${GREEN}✓ All setup complete!${NC}"
echo -e "Start the platform using: ${YELLOW}npm run dev${NC} or ${YELLOW}npm start${NC}"
