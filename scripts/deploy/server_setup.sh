#!/bin/bash
# Script para desplegar el servidor Flask en un entorno de producción

# Variables de configuración (CORREGIDAS)
APP_NAME="botfarm"
DOMAIN="botfarm.example.com"
APP_DIR="/var/www/$APP_NAME"
VENV_DIR="$APP_DIR/venv"
GIT_REPO="https://github.com/yourusername/botfarm.git"
FLASK_APP="app"
FLASK_ENV="production"
SERVER_DIR="$APP_DIR/server"  # Directorio correcto donde está Flask

# Actualizar el sistema
echo "Actualizando el sistema..."
sudo apt update
sudo apt upgrade -y

# Instalar dependencias
echo "Instalando dependencias..."
sudo apt install -y python3 python3-venv python3-dev build-essential libssl-dev \
     libffi-dev git nginx postgresql postgresql-contrib redis-server supervisor

# Crear usuario para la aplicación (sin acceso a shell)
echo "Configurando usuario de la aplicación..."
sudo useradd -m -s /bin/false $APP_NAME || true

# Crear directorio de la aplicación
echo "Creando directorio de la aplicación..."
sudo mkdir -p $APP_DIR
sudo chown $APP_NAME:$APP_NAME $APP_DIR

# Clonar repositorio
echo "Clonando repositorio..."
sudo -u $APP_NAME git clone $GIT_REPO $APP_DIR

# Crear entorno virtual
echo "Configurando entorno virtual..."
sudo -u $APP_NAME python3 -m venv $VENV_DIR

# Instalar dependencias
echo "Instalando dependencias de Python..."
sudo -u $APP_NAME $VENV_DIR/bin/pip install --upgrade pip
sudo -u $APP_NAME $VENV_DIR/bin/pip install -r $SERVER_DIR/requirements.txt  # Ruta corregida
sudo -u $APP_NAME $VENV_DIR/bin/pip install gunicorn eventlet

# Configurar variables de entorno
echo "Configurando variables de entorno..."
cat > $APP_DIR/.env << EOF
FLASK_APP=$FLASK_APP
FLASK_ENV=$FLASK_ENV
SECRET_KEY=$(openssl rand -hex 32)
DATABASE_URL=postgresql://botfarm:$(openssl rand -hex 16)@localhost:5432/botfarm
REDIS_URL=redis://localhost:6379/0
OPENAI_API_KEY=your_openai_api_key_here
EOF

sudo chown $APP_NAME:$APP_NAME $APP_DIR/.env
sudo chmod 600 $APP_DIR/.env

# Configurar base de datos PostgreSQL
echo "Configurando base de datos..."
sudo -u postgres psql -c "CREATE USER botfarm WITH PASSWORD '$(grep DATABASE_URL $APP_DIR/.env | cut -d ':' -f 3 | cut -d '@' -f 1)';"
sudo -u postgres psql -c "CREATE DATABASE botfarm OWNER botfarm;"

# Inicializar la base de datos
echo "Inicializando la base de datos..."
cd $SERVER_DIR  # Directorio corregido
sudo -u $APP_NAME $VENV_DIR/bin/flask db upgrade

# Configurar Supervisor
echo "Configurando Supervisor..."
cat > /etc/supervisor/conf.d/botfarm.conf << EOF
[program:$APP_NAME]
directory=$SERVER_DIR  # Directorio corregido
command=$VENV_DIR/bin/gunicorn -k eventlet -w 1 --bind unix:$APP_DIR/botfarm.sock wsgi:app
user=$APP_NAME
autostart=true
autorestart=true
stopasgroup=true
killasgroup=true
stderr_logfile=/var/log/supervisor/$APP_NAME.err.log
stdout_logfile=/var/log/supervisor/$APP_NAME.out.log
environment=
    FLASK_APP=$FLASK_APP,
    FLASK_ENV=$FLASK_ENV,
    SECRET_KEY="$(grep SECRET_KEY $APP_DIR/.env | cut -d '=' -f 2)",
    DATABASE_URL="$(grep DATABASE_URL $APP_DIR/.env | cut -d '=' -f 2-)",
    REDIS_URL="$(grep REDIS_URL $APP_DIR/.env | cut -d '=' -f 2)",
    OPENAI_API_KEY="$(grep OPENAI_API_KEY $APP_DIR/.env | cut -d '=' -f 2)"
EOF

# Configurar Nginx
echo "Configurando Nginx..."
cat > /etc/nginx/sites-available/$APP_NAME << EOF
server {
    listen 80;
    server_name $DOMAIN;

    location / {
        proxy_pass http://unix:$APP_DIR/botfarm.sock;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location /socket.io {
        proxy_pass http://unix:$APP_DIR/botfarm.sock;
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    location /static {
        alias $SERVER_DIR/app/static;  # Directorio corregido
    }
}
EOF

# Activar configuración de Nginx
sudo ln -sf /etc/nginx/sites-available/$APP_NAME /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default

# Reiniciar servicios
echo "Reiniciando servicios..."
sudo systemctl restart supervisor
sudo systemctl restart nginx

# Configurar Certbot para HTTPS
echo "Configurando HTTPS con Certbot..."
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d $DOMAIN --non-interactive --agree-tos -m admin@example.com

echo "===================================="
echo "Despliegue completado correctamente!"
echo "El servidor está disponible en https://$DOMAIN"
echo "===================================="
