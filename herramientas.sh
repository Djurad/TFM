#!/bin/bash

set -e

echo "[+] Setup"

# Go

if command -v go >/dev/null 2>&1; then
echo "[+] Go OK"
else
sudo snap install go --classic
fi

# PATH (guardar + usar ahora)

if ! grep -q 'export PATH=$PATH:$HOME/go/bin:/snap/bin' ~/.bashrc; then
echo 'export PATH=$PATH:$HOME/go/bin:/snap/bin' >> ~/.bashrc
fi

export PATH=$PATH:$HOME/go/bin:/snap/bin

# Función para tools

instalar_tool() {
if command -v "$1" >/dev/null 2>&1; then
echo "[+] $1 OK"
else
go install "$2"
fi
}

# Tools

instalar_tool subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
instalar_tool httpx github.com/projectdiscovery/httpx/cmd/httpx@latest
instalar_tool katana github.com/projectdiscovery/katana/cmd/katana@latest
instalar_tool nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

echo "[+] OK"

