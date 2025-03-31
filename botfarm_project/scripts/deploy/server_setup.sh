#!/bin/bash
# Script para desplegar el servidor Flask en un entorno de producción

# Variables de configuración
APP_NAME="botfarm"
DOMAIN="botfarm.example.com"
APP_DIR="/var/www/$APP_NAME"
VENV_DIR="$APP_DIR/venv"
GIT_REPO="https://github.com/yourusername/botfarm-server.git"
FLASK_APP="app"
FLASK_ENV="production"

# Actualizar el sistema
echo "Actualizando el sistema..."
sudo apt update
sudo apt upgrade -y

# Instalar dependencias
echo "Instalando dependencias..."
sudo apt install -y python3 python3-venv python3-dev build-essential libssl-dev \
     libffi-dev git nginx postgresql postgresql-contrib redis-server supervisor

# Resto del script...
