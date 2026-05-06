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

echo "[+] Verificando herramientas..."
subfinder -version || true
httpx -version || true
katana -version || true
nuclei -version || true

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