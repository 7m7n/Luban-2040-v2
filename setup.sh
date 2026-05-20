#!/usr/bin/env bash
# ======================================================
#  Luban 2040 v2 – Setup (Linux / macOS)
#  Author: m.alfahdi
# ======================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${RED}"
echo "  _                 _                   ____   ___    _  _    ___  "
echo " | |    _   _  ___ | |__    __ _  _ __ |___ \ / _ \  | || |  / _ \ "
echo " | |   | | | |/ _ \| '_ \  / _\` || '_ \  __) | | | | | || |_| | | |"
echo " | |___| |_| |  __/| |_) || (_| || | | |/ __/| |_| | |__   _| |_| |"
echo " |_____|\__,_|\___||_.__/  \__,_||_| |_|_____|\___/     |_|  \___/ "
echo -e "${NC}"
echo -e "${YELLOW}                v2  Setup for Linux/macOS${NC}"
echo ""

# 1. Check Python 3
echo -e "${CYAN}[*] Checking Python 3...${NC}"
if command -v python3 &>/dev/null; then
    PYTHON=python3
elif command -v python &>/dev/null; then
    PYTHON=python
else
    echo -e "${RED}[!] Python 3 not found. Install it first (apt install python3 / brew install python3).${NC}"
    exit 1
fi
echo -e "${GREEN}[✓] Found: $($PYTHON --version)${NC}"

# 2. Check pip
echo -e "${CYAN}[*] Checking pip...${NC}"
if ! $PYTHON -m pip --version &>/dev/null; then
    echo -e "${RED}[!] pip not found. Run: $PYTHON -m ensurepip${NC}"
    exit 1
fi
echo -e "${GREEN}[✓] pip is available${NC}"

# 3. Install required libraries
echo -e "${CYAN}[*] Installing core libraries (this may take a minute)...${NC}"
$PYTHON -m pip install --upgrade pip
$PYTHON -m pip install -r requirements.txt
echo -e "${GREEN}[✓] Core libraries installed${NC}"

# 4. Optional: Scrapling (Cloudflare bypass)
echo ""
echo -e "${YELLOW}[?] Install optional Scrapling engine?${NC}"
echo -e "${YELLOW}    (Cloudflare bypass + JavaScript rendering)${NC}"
read -p "    Install Scrapling? [y/N]: " answer
if [[ "$answer" =~ ^[Yy]$ ]]; then
    echo -e "${CYAN}[*] Installing Scrapling...${NC}"
    $PYTHON -m pip install "scrapling[fetchers]"
    echo -e "${CYAN}[*] Downloading browser binaries (one-time) ...${NC}"
    scrapling install
    echo -e "${GREEN}[✓] Scrapling ready${NC}"
else
    echo -e "${CYAN}[*] Skipping Scrapling. Tool will use standard HTTP.${NC}"
fi

# 5. Create necessary folders
mkdir -p core data

# 6. Reminder
echo ""
echo -e "${YELLOW}[!] Reminder:${NC}"
echo -e "    Open ${CYAN}config.json${NC} and add your Shodan API key if you need:"
echo -e "       -org / -q   (Shodan searches)"
echo -e "    DNS-based scanning (-host / -web) works without any key."
echo ""
echo -e "${GREEN}[✓] All set!${NC}"
echo -e "    Run: ${GREEN}$PYTHON luban2040.py -h${NC}"