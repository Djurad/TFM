#!/bin/bash setup

set -e

echo "======================================"
echo "   SETUP AUTOMATICO - PROYECTO TFM"
echo "======================================"

echo "[+] Actualizando sistema..."
sudo apt update
sudo apt upgrade -y

echo "[+] Instalando paquetes base..."
sudo apt install -y git curl wget unzip build-essential jq
sudo apt install -y cargo || true

echo "[+] Instalando Node.js 20..."
sudo apt remove -y nodejs libnode-dev nodejs-doc || true
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt --fix-broken install -y
sudo apt install -y nodejs

echo "[+] Versiones instaladas:"
node -v
npm -v

echo "[+] Instalando Go..."
sudo apt install -y golang

echo "[+] Configurando PATH de Go..."
if ! grep -q 'export PATH=$PATH:$HOME/go/bin' ~/.bashrc; then
    echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
fi

export PATH=$PATH:$HOME/go/bin

echo "[+] Version de Go:"
go version

echo "[+] Instalando herramientas de reconocimiento web..."

echo "    - subfinder"
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

echo "    - httpx"
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

echo "    - katana"
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

echo "    - nuclei"
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

echo "    - dalfox"
go install -v github.com/hahwul/dalfox/v2@latest

echo "    - gau"
go install -v github.com/lc/gau/v2/cmd/gau@latest

echo "    - gf"
go install -v github.com/tomnomnom/gf@latest

echo "[+] Instalando patrones de gf..."
mkdir -p "$HOME/.gf"
if [ ! -d "/tmp/Gf-Patterns" ]; then
    git clone https://github.com/1ndianl33t/Gf-Patterns /tmp/Gf-Patterns || true
fi
cp /tmp/Gf-Patterns/*.json "$HOME/.gf" 2>/dev/null || true

echo "[+] Instalando feroxbuster..."
if command -v cargo >/dev/null 2>&1; then
    cargo install feroxbuster || true
else
    sudo apt install -y feroxbuster || true
fi

echo "[+] Instalando trufflehog..."
if ! command -v trufflehog >/dev/null 2>&1; then
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh || true
fi

echo "[+] Verificando herramientas..."
subfinder -version || true
httpx -version || true
katana -version || true
nuclei -version || true
dalfox version || true
gau --version || true
gf -h >/dev/null 2>&1 || true
feroxbuster --version || true
trufflehog --version || true

echo "[+] Actualizando templates de nuclei..."
nuclei -update-templates || true

echo "[+] Instalando dependencias del backend..."

if [ -d "backend" ]; then
    cd backend

    if [ -f "package.json" ]; then
        npm install
    else
        echo "[!] No existe package.json. Inicializando proyecto Node..."
        npm init -y
        npm install express cors pdfkit dotenv
    fi

    cd ..
else
    echo "[!] No existe carpeta backend. Creándola..."
    mkdir backend
    cd backend
    npm init -y
    npm install express cors pdfkit dotenv
    cd ..
fi

echo "======================================"
echo "   INSTALACION COMPLETADA"
echo "======================================"
echo ""
echo "Para aplicar el PATH de Go ejecuta:"
echo "source ~/.bashrc"
echo ""
echo "Para arrancar el backend:"
echo "cd backend"
echo "node server.js" 
