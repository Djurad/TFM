#!/bin/bash

set -e

echo "[+] Setup"

# Dependencias base

sudo apt update
sudo apt install -y nodejs npm git curl cargo nmap

# Instalar dependencias npm del proyecto

npm install

# Go

if command -v go >/dev/null 2>&1; then
  echo "[+] Go OK"
else
  sudo snap install go --classic
fi

# PATH Go / Snap / Cargo

if ! grep -q 'export PATH=$PATH:$HOME/go/bin:/snap/bin:$HOME/.cargo/bin' ~/.bashrc; then
  echo 'export PATH=$PATH:$HOME/go/bin:/snap/bin:$HOME/.cargo/bin' >> ~/.bashrc
fi

export PATH=$PATH:$HOME/go/bin:/snap/bin:$HOME/.cargo/bin

# Función para instalar tools Go

instalar_tool() {
  if command -v "$1" >/dev/null 2>&1; then
    echo "[+] $1 OK"
  else
    echo "[+] Instalando $1"
    go install "$2"
  fi
}

# =========================
# Tools principales
# =========================

instalar_tool subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
instalar_tool httpx github.com/projectdiscovery/httpx/cmd/httpx@latest
instalar_tool katana github.com/projectdiscovery/katana/cmd/katana@latest
instalar_tool nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
instalar_tool dalfox github.com/hahwul/dalfox/v2@latest

# =========================
# Nuevas herramientas
# =========================

instalar_tool gf github.com/tomnomnom/gf@latest
instalar_tool gau github.com/lc/gau/v2/cmd/gau@latest

# =========================
# GF Patterns
# =========================

echo "[+] Comprobando GF patterns"

mkdir -p "$HOME/.gf"

if [ -z "$(ls -A "$HOME/.gf" 2>/dev/null)" ]; then
  echo "[+] Instalando GF patterns"

  rm -rf /tmp/Gf-Patterns
  git clone https://github.com/1ndianl33t/Gf-Patterns /tmp/Gf-Patterns
  cp /tmp/Gf-Patterns/*.json "$HOME/.gf/"
  rm -rf /tmp/Gf-Patterns
else
  echo "[+] GF patterns OK"
fi

echo "[+] Patterns GF disponibles:"
gf -list || true

# =========================
# Feroxbuster
# =========================

if command -v feroxbuster >/dev/null 2>&1; then
  echo "[+] feroxbuster OK"
else
  echo "[+] Instalando feroxbuster"

  if command -v cargo >/dev/null 2>&1; then
    cargo install feroxbuster
  else
    sudo apt install -y feroxbuster || true
  fi
fi

# =========================
# Trufflehog
# =========================

if command -v trufflehog >/dev/null 2>&1; then
  echo "[+] trufflehog OK"
else
  echo "[+] Instalando trufflehog"

  curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh

  if [ -f "./bin/trufflehog" ]; then
    sudo mv ./bin/trufflehog /usr/local/bin/trufflehog
  fi
fi

# =========================
# sqlmap
# =========================

if [ -d "tools/sqlmap" ]; then
  echo "[+] sqlmap OK"
else
  echo "[+] Instalando sqlmap"

  mkdir -p tools
  git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git tools/sqlmap
fi

# =========================
# Templates nuclei
# =========================

echo "[+] Actualizando templates de nuclei"

nuclei -update-templates || true

echo "[+] Setup completado"

echo "[+] Comprueba herramientas:"
echo "subfinder -version"
echo "httpx -version"
echo "katana -version"
echo "nuclei -version"
echo "dalfox version"
echo "gf -list"
echo "gau --version"
echo "feroxbuster --help"
echo "trufflehog --help"
echo "nmap --version"
