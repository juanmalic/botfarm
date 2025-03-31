    def get_auth_data(self):
        """Convierte el texto JSON de auth_data a diccionario (desencriptado)"""
        if not self.auth_data:
            return {}
        try:
            # Aquí se implementaría la desencriptación
            return json.loads(self.auth_data)
        except json.JSONDecodeError:
            return {}
    
    def set_auth_data(self, auth_dict):
        """Convierte un diccionario a texto JSON para auth_data (encriptado)"""
        if auth_dict:
            # Aquí se implementaría la encriptación
            self.auth_data = json.dumps(auth_dict)
        else:
            self.auth_data = None
    
    def to_dict(self):
        return {
            'id': self.id,
            'device_id': self.device_id,
            'platform': self.platform,
            'username': self.username,
            'status': self.status,
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'created_at': self.created_at.isoformat(),
            'followers_count': self.followers_count,
            'following_count': self.following_count,
            'posts_count': self.posts_count,
            'last_stats_update': self.last_stats_update.isoformat() if self.last_stats_update else None,
        }
    
    def __repr__(self):
        return f'<SocialAccount {self.platform}:{self.username}>'


class SocialPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    account_id = db.Column(db.Integer, db.ForeignKey('social_account.id'), nullable=False)
    platform = db.Column(db.String(32), nullable=False, index=True)
    post_id = db.Column(db.String(64), nullable=True)  # ID del post en la plataforma
    content = db.Column(db.Text, nullable=False)
    media_urls = db.Column(db.Text, nullable=True)  # JSON con URLs de medios
    status = db.Column(db.String(16), default='draft', index=True)  # draft, published, failed
    published_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Estadísticas
    likes_count = db.Column(db.Integer, default=0)
    comments_count = db.Column(db.Integer, default=0)
    shares_count = db.Column(db.Integer, default=0)
    
    def get_media_urls(self):
        if not self.media_urls:
            return []
        try:
            return json.loads(self.media_urls)
        except json.JSONDecodeError:
            return []
    
    def set_media_urls(self, urls_list):
        if urls_list:
            self.media_urls = json.dumps(urls_list)
        else:
            self.media_urls = None
    
    def to_dict(self):
        return {
            'id': self.id,
            'account_id': self.account_id,
            'platform': self.platform,
            'post_id': self.post_id,
            'content': self.content,
            'media_urls': self.get_media_urls(),
            'status': self.status,
            'published_at': self.published_at.isoformat() if self.published_at else None,
            'created_at': self.created_at.isoformat(),
            'likes_count': self.likes_count,
            'comments_count': self.comments_count,
            'shares_count': self.shares_count
        }
    
    def __repr__(self):
        return f'<SocialPost {self.id}>'
EOF

# Crear los módulos básicos
echo "Creando módulos del panel..."

# Autenticación
cat > app/auth/__init__.py << 'EOF'
from flask import Blueprint

auth = Blueprint('auth', __name__)

from . import routes
EOF

cat > app/auth/forms.py << 'EOF'
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from app.models.user import User

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(),
        Email(),
        Length(1, 120)
    ])
    password = PasswordField('Contraseña', validators=[
        DataRequired()
    ])
    remember_me = BooleanField('Mantener sesión iniciada')
    submit = SubmitField('Iniciar Sesión')


class RegistrationForm(FlaskForm):
    username = StringField('Nombre de usuario', validators=[
        DataRequired(),
        Length(3, 64),
        Regexp('^[A-Za-z][A-Za-z0-9_.]*#!/bin/bash

# Script para generar la estructura de carpetas y archivos del Panel BotFarm
# Ejecutar este script dentro de la carpeta "server" del proyecto BotFarm

echo "====== Generando estructura de carpetas y archivos del Panel BotFarm ======"

# Crear la estructura de directorios
echo "Creando estructura de directorios..."

# Crear directorios principales
mkdir -p app/api
mkdir -p app/auth
mkdir -p app/dashboard
mkdir -p app/devices
mkdir -p app/models
mkdir -p app/social
mkdir -p app/tasks
mkdir -p app/templates/{auth,dashboard,devices,social,tasks}
mkdir -p app/static/{css,js,img,uploads}
mkdir -p app/websocket

# Crear archivos de inicialización
echo "Creando archivos de inicialización Python..."

# Crear archivos __init__.py
touch app/__init__.py
touch app/api/__init__.py
touch app/auth/__init__.py
touch app/dashboard/__init__.py
touch app/devices/__init__.py
touch app/models/__init__.py
touch app/social/__init__.py
touch app/tasks/__init__.py
touch app/websocket/__init__.py

# Crear archivos principales
echo "Creando archivos principales..."

# Archivos de configuración y ejecución
cat > config.py << 'EOF'
import os
from datetime import timedelta

class Config:
    # Configuración básica
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev_key_change_in_production')
    DEBUG = False
    TESTING = False
    
    # Configuración de la base de datos
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///botfarm.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Configuración de sesión
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)
    
    # Configuración de OpenAI
    OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY')
    
    # Configuración de WebSocket
    SOCKETIO_PING_TIMEOUT = 10
    SOCKETIO_PING_INTERVAL = 5
    
    # Configuración de upload
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'app/static/uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB máximo

class DevelopmentConfig(Config):
    DEBUG = True
    
class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    
class ProductionConfig(Config):
    # En producción, asegúrate de tener estas variables configuradas
    DEBUG = False
    
    # Configuración de seguridad adicional
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_HTTPONLY = True

# Diccionario de configuraciones
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
EOF

cat > wsgi.py << 'EOF'
from app import create_app, socketio

app = create_app('production')

if __name__ == '__main__':
    socketio.run(app)
EOF

cat > run.py << 'EOF'
#!/usr/bin/env python
from app import create_app, socketio, db
from app.models.user import User
from app.models.device import Device, DeviceLog
from app.models.task import Task
from app.models.social_account import SocialAccount, SocialPost
from datetime import datetime, timedelta
import os
import click
import json

app = create_app('development')

@app.shell_context_processor
def make_shell_context():
    return dict(
        app=app, db=db, 
        User=User, Device=Device, DeviceLog=DeviceLog,
        Task=Task, SocialAccount=SocialAccount, 
        SocialPost=SocialPost
    )

@app.cli.command("create-admin")
@click.argument("username")
@click.argument("email")
@click.argument("password")
def create_admin(username, email, password):
    """Crea un usuario administrador"""
    if User.query.filter_by(username=username).first():
        click.echo(f"Usuario {username} ya existe.")
        return
    
    if User.query.filter_by(email=email).first():
        click.echo(f"Email {email} ya está registrado.")
        return
    
    user = User(username=username, email=email, is_admin=True)
    user.password = password
    db.session.add(user)
    db.session.commit()
    click.echo(f"Usuario administrador {username} creado correctamente.")

@app.cli.command("init-db")
def init_db():
    """Inicializa la base de datos con datos de ejemplo"""
    # Eliminar datos existentes
    db.drop_all()
    db.create_all()
    
    # Crear usuario admin
    admin = User(
        username="admin",
        email="admin@example.com",
        is_admin=True
    )
    admin.password = "admin123"
    db.session.add(admin)
    
    # Crear algunos dispositivos de ejemplo
    devices = [
        Device(
            device_id="device_1",
            name="Dispositivo 1",
            status="online",
            model="Samsung Galaxy S10",
            android_version="11",
            battery_level=85,
            ip_address="192.168.1.100",
            last_seen=datetime.utcnow()
        ),
        Device(
            device_id="device_2",
            name="Dispositivo 2",
            status="offline",
            model="Xiaomi Redmi Note 9",
            android_version="10",
            battery_level=45,
            last_seen=datetime.utcnow() - timedelta(hours=5)
        ),
        Device(
            device_id="device_3",
            name="Dispositivo 3",
            status="error",
            model="Google Pixel 4",
            android_version="12",
            battery_level=12,
            last_seen=datetime.utcnow() - timedelta(minutes=30)
        )
    ]
    
    for device in devices:
        db.session.add(device)
    
    # Crear tareas de ejemplo
    tasks = [
        Task(
            device_id=1,
            name="Publicar en Twitter",
            type="social_post",
            status="completed",
            priority=5,
            scheduled_at=datetime.utcnow() - timedelta(hours=2),
            started_at=datetime.utcnow() - timedelta(hours=2),
            completed_at=datetime.utcnow() - timedelta(hours=1, minutes=55)
        ),
        Task(
            device_id=1,
            name="Recopilar datos de Instagram",
            type="data_scraping",
            status="in_progress",
            priority=3,
            started_at=datetime.utcnow() - timedelta(minutes=15)
        ),
        Task(
            device_id=2,
            name="Reiniciar dispositivo",
            type="system",
            status="pending",
            priority=10,
            scheduled_at=datetime.utcnow() + timedelta(hours=1)
        ),
        Task(
            device_id=3,
            name="Actualizar firmware",
            type="system",
            status="failed",
            priority=8,
            started_at=datetime.utcnow() - timedelta(hours=1),
            completed_at=datetime.utcnow() - timedelta(minutes=50),
            error_message="No se pudo acceder al servidor de actualización"
        )
    ]
    
    for task in tasks:
        db.session.add(task)
    
    # Configurar parámetros para las tareas
    tasks[0].set_parameters({
        "platform": "twitter",
        "content": "¡Hola mundo desde BotFarm! #automatización #bots",
        "media_urls": []
    })
    
    tasks[0].set_result({
        "success": True,
        "post_id": "1234567890",
        "url": "https://twitter.com/user/status/1234567890"
    })
    
    tasks[1].set_parameters({
        "platform": "instagram",
        "username": "target_user",
        "data_type": "followers",
        "max_items": 100
    })
    
    tasks[2].set_parameters({
        "command": "restart",
        "delay": 0
    })
    
    tasks[3].set_parameters({
        "firmware_version": "2.0.1",
        "force_update": True
    })
    
    # Crear cuentas sociales de ejemplo
    accounts = [
        SocialAccount(
            device_id=1,
            platform="twitter",
            username="bot_user1",
            status="active",
            followers_count=250,
            following_count=100,
            posts_count=75,
            last_used=datetime.utcnow() - timedelta(hours=2),
            last_stats_update=datetime.utcnow() - timedelta(hours=12)
        ),
        SocialAccount(
            device_id=1,
            platform="instagram",
            username="bot_insta",
            status="active",
            followers_count=520,
            following_count=300,
            posts_count=45,
            last_used=datetime.utcnow() - timedelta(days=1),
            last_stats_update=datetime.utcnow() - timedelta(days=1)
        ),
        SocialAccount(
            device_id=2,
            platform="facebook",
            username="bot_fb_user",
            status="inactive",
            followers_count=0,
            following_count=0,
            posts_count=0
        )
    ]
    
    for account in accounts:
        db.session.add(account)
    
    # Configurar datos de autenticación para las cuentas
    accounts[0].set_auth_data({
        "api_key": "dummy_api_key_1",
        "api_secret": "dummy_api_secret_1",
        "access_token": "dummy_access_token_1",
        "access_secret": "dummy_access_secret_1"
    })
    
    accounts[1].set_auth_data({
        "username": "bot_insta",
        "password": "dummy_password",
        "auth_token": "dummy_auth_token_2"
    })
    
    # Crear publicaciones de ejemplo
    posts = [
        SocialPost(
            account_id=1,
            platform="twitter",
            post_id="1234567890",
            content="¡Hola mundo desde BotFarm! #automatización #bots",
            status="published",
            published_at=datetime.utcnow() - timedelta(hours=2),
            likes_count=15,
            comments_count=3,
            shares_count=5
        ),
        SocialPost(
            account_id=2,
            platform="instagram",
            content="Automatizando con BotFarm #tech #automation",
            media_urls=json.dumps(["/static/uploads/example_image.jpg"]),
            status="draft"
        )
    ]
    
    for post in posts:
        db.session.add(post)
    
    # Crear logs de ejemplo
    logs = [
        DeviceLog(
            device_id=1,
            level="info",
            message="Dispositivo iniciado correctamente",
            timestamp=datetime.utcnow() - timedelta(hours=5)
        ),
        DeviceLog(
            device_id=1,
            level="info",
            message="Tarea de publicación en Twitter completada",
            timestamp=datetime.utcnow() - timedelta(hours=1, minutes=55)
        ),
        DeviceLog(
            device_id=2,
            level="warning",
            message="Batería baja (20%)",
            timestamp=datetime.utcnow() - timedelta(hours=3)
        ),
        DeviceLog(
            device_id=3,
            level="error",
            message="Error al actualizar firmware: No se pudo acceder al servidor",
            timestamp=datetime.utcnow() - timedelta(minutes=50)
        )
    ]
    
    for log in logs:
        db.session.add(log)
    
    # Guardar todos los cambios
    db.session.commit()
    
    click.echo("Base de datos inicializada con datos de ejemplo.")

if __name__ == '__main__':
    # Asegurarse de que la carpeta de uploads exista
    uploads_dir = os.path.join(app.static_folder, 'uploads')
    if not os.path.exists(uploads_dir):
        os.makedirs(uploads_dir)
    
    # Ejecutar la aplicación con WebSocket
    socketio.run(app, debug=app.config['DEBUG'], host='0.0.0.0')
EOF

cat > requirements.txt << 'EOF'
Flask==2.2.3
Flask-SQLAlchemy==3.0.3
Flask-Migrate==4.0.4
Flask-Login==0.6.2
Flask-WTF==1.1.1
Flask-SocketIO==5.3.3
python-dotenv==1.0.0
gunicorn==20.1.0
eventlet==0.33.3
psycopg2-binary==2.9.6
redis==4.5.4
openai==0.27.6
requests==2.29.0
pytz==2023.3
cryptography==40.0.2
email_validator==2.0.0
WTForms==3.0.1
SQLAlchemy==2.0.10
Werkzeug==2.2.3
itsdangerous==2.1.2
Jinja2==3.1.2
MarkupSafe==2.1.2
EOF

cat > README.md << 'EOF'
# BotFarm - Panel de Control

Panel de administración web para la gestión de bots móviles Android. Este panel permite controlar múltiples dispositivos, programar tareas, gestionar cuentas de redes sociales y monitorear la actividad de los bots.

## Características

- **Gestión de Dispositivos**: Monitoreo en tiempo real de dispositivos Android
- **Tareas Programadas**: Creación y seguimiento de tareas para los dispositivos
- **Cuentas de Redes Sociales**: Administración de cuentas de Twitter, Instagram y otras plataformas
- **Publicaciones**: Programación y seguimiento de publicaciones en redes sociales
- **Generación de Contenido**: Integración con OpenAI para generar contenido
- **WebSockets**: Comunicación en tiempo real entre el servidor y los dispositivos

## Requisitos

- Python 3.8+
- PostgreSQL
- Redis (para WebSockets)
- Cuenta en OpenAI (opcional, para generación de contenido)

## Instalación

1. Clonar el repositorio:
```bash
git clone https://github.com/tuusuario/botfarm-panel.git
cd botfarm-panel
```

2. Crear y activar un entorno virtual:
```bash
python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate
```

3. Instalar las dependencias:
```bash
pip install -r requirements.txt
```

4. Configurar las variables de entorno:
```bash
cp .env.example .env
# Editar .env con los valores adecuados
```

5. Inicializar la base de datos:
```bash
flask init-db
```

6. Crear un usuario administrador:
```bash
flask create-admin admin admin@example.com password123
```

## Ejecución

Para desarrollo:
```bash
python run.py
```

Para producción, se recomienda usar Gunicorn con Eventlet:
```bash
gunicorn -k eventlet -w 1 --bind 0.0.0.0:5000 wsgi:app
```

## Estructura del Proyecto

```
botfarm-panel/
├── app/                  # Aplicación principal
│   ├── api/              # API REST
│   ├── auth/             # Autenticación
│   ├── dashboard/        # Panel principal
│   ├── devices/          # Gestión de dispositivos
│   ├── models/           # Modelos de base de datos
│   ├── social/           # Redes sociales
│   ├── tasks/            # Gestión de tareas
│   ├── templates/        # Plantillas HTML
│   ├── static/           # Archivos estáticos
│   └── websocket/        # Manejadores de WebSocket
├── config.py             # Configuración
├── requirements.txt      # Dependencias
├── run.py                # Script para ejecutar en desarrollo
└── wsgi.py               # Punto de entrada para producción
```

## Uso con la App Android

Para que los dispositivos se conecten al panel, deben tener instalada la aplicación BotFarm para Android. La aplicación se configura con la URL del panel y se registra automáticamente.

## Seguridad

El panel utiliza:
- Autenticación de usuarios con Flask-Login
- Tokens CSRF para prevenir ataques CSRF
- Validación de datos de entrada
- Cifrado de datos sensibles (tokens de API, contraseñas, etc.)
- Conexiones seguras mediante WebSockets

## Licencia

Este proyecto está licenciado bajo la Licencia MIT. Consulte el archivo LICENSE para más detalles.

## Contribuciones

Las contribuciones son bienvenidas. Por favor, abra un issue o envíe un pull request para colaborar.
EOF

# Crear archivos de la aplicación principal
cat > app/__init__.py << 'EOF'
from flask import Flask, render_template
from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from config import config
import os

# Inicializar extensiones
db = SQLAlchemy()
migrate = Migrate()
socketio = SocketIO()
login_manager = LoginManager()
csrf = CSRFProtect()

def create_app(config_name='default'):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    
    # Asegurar que existe el directorio de uploads
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    
    # Inicializar extensiones con la app
    db.init_app(app)
    migrate.init_app(app, db)
    socketio.init_app(app, cors_allowed_origins="*", async_mode='eventlet')
    login_manager.init_app(app)
    csrf.init_app(app)
    
    # Configurar login
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Por favor inicia sesión para acceder a esta página.'
    
    # Registrar blueprints
    from app.api import api as api_blueprint
    app.register_blueprint(api_blueprint, url_prefix='/api')
    
    from app.auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/auth')
    
    from app.dashboard import dashboard as dashboard_blueprint
    app.register_blueprint(dashboard_blueprint)
    
    from app.devices import devices as devices_blueprint
    app.register_blueprint(devices_blueprint, url_prefix='/devices')
    
    from app.tasks import tasks as tasks_blueprint
    app.register_blueprint(tasks_blueprint, url_prefix='/tasks')
    
    from app.social import social as social_blueprint
    app.register_blueprint(social_blueprint, url_prefix='/social')
    
    from app.websocket import register_handlers
    register_handlers(socketio)
    
    # Manejador de errores 404
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('404.html'), 404
    
    # Manejador de errores 500
    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template('500.html'), 500
    
    return app
EOF

# Crear modelos
echo "Creando modelos de datos..."

cat > app/models/user.py << 'EOF'
from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import uuid

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    api_key = db.Column(db.String(64), unique=True, index=True, nullable=True)
    last_login = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.api_key is None:
            self.api_key = str(uuid.uuid4())
    
    @property
    def password(self):
        raise AttributeError('La contraseña no es un atributo legible')
    
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def generate_api_key(self):
        self.api_key = str(uuid.uuid4())
        return self.api_key
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'is_admin': self.is_admin,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'created_at': self.created_at.isoformat()
        }
    
    def __repr__(self):
        return f'<User {self.username}>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
EOF

cat > app/models/device.py << 'EOF'
from app import db
from datetime import datetime

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    name = db.Column(db.String(64), nullable=True)
    status = db.Column(db.String(16), default='offline', index=True)  # online, offline, error
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    model = db.Column(db.String(64), nullable=True)
    android_version = db.Column(db.String(32), nullable=True)
    battery_level = db.Column(db.Integer, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relaciones
    tasks = db.relationship('Task', backref='device', lazy=True, cascade='all, delete-orphan')
    social_accounts = db.relationship('SocialAccount', backref='device', lazy=True, cascade='all, delete-orphan')
    logs = db.relationship('DeviceLog', backref='device', lazy=True, cascade='all, delete-orphan')
    
    def is_active(self):
        """Comprueba si el dispositivo está activo (visto en los últimos 5 minutos)"""
        if not self.last_seen:
            return False
        delta = datetime.utcnow() - self.last_seen
        return delta.total_seconds() < 300  # 5 minutos
    
    def to_dict(self):
        return {
            'id': self.id,
            'device_id': self.device_id,
            'name': self.name,
            'status': self.status,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'model': self.model,
            'android_version': self.android_version,
            'battery_level': self.battery_level,
            'ip_address': self.ip_address,
            'is_active': self.is_active(),
            'created_at': self.created_at.isoformat(),
            'social_accounts_count': len(self.social_accounts),
            'tasks_count': len(self.tasks)
        }
    
    def __repr__(self):
        return f'<Device {self.device_id}>'


class DeviceLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    level = db.Column(db.String(10), default='info', index=True)  # info, warning, error
    message = db.Column(db.Text, nullable=False)
    
    def to_dict(self):
        return {
            'id': self.id,
            'device_id': self.device_id,
            'timestamp': self.timestamp.isoformat(),
            'level': self.level,
            'message': self.message
        }
    
    def __repr__(self):
        return f'<DeviceLog {self.id}>'
EOF

cat > app/models/task.py << 'EOF'
from app import db
from datetime import datetime
import json

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False, index=True)
    name = db.Column(db.String(64), nullable=False)
    type = db.Column(db.String(32), nullable=False, index=True)  # social_post, data_scraping, etc.
    status = db.Column(db.String(16), default='pending', index=True)  # pending, in_progress, completed, failed
    priority = db.Column(db.Integer, default=0, index=True)  # Mayor número = mayor prioridad
    parameters = db.Column(db.Text, nullable=True)  # JSON con parámetros
    result = db.Column(db.Text, nullable=True)  # JSON con resultado
    error_message = db.Column(db.Text, nullable=True)
    scheduled_at = db.Column(db.DateTime, nullable=True, index=True)
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    def get_parameters(self):
        """Convierte el texto JSON de parámetros a diccionario"""
        if not self.parameters:
            return {}
        try:
            return json.loads(self.parameters)
        except json.JSONDecodeError:
            return {}
    
    def set_parameters(self, params_dict):
        """Convierte un diccionario a texto JSON para parámetros"""
        if params_dict:
            self.parameters = json.dumps(params_dict)
        else:
            self.parameters = None
    
    def get_result(self):
        """Convierte el texto JSON de resultado a diccionario"""
        if not self.result:
            return {}
        try:
            return json.loads(self.result)
        except json.JSONDecodeError:
            return {}
    
    def set_result(self, result_dict):
        """Convierte un diccionario a texto JSON para resultado"""
        if result_dict:
            self.result = json.dumps(result_dict)
        else:
            self.result = None
    
    def to_dict(self):
        return {
            'id': self.id,
            'device_id': self.device_id,
            'name': self.name,
            'type': self.type,
            'status': self.status,
            'priority': self.priority,
            'parameters': self.get_parameters(),
            'result': self.get_result(),
            'error_message': self.error_message,
            'scheduled_at': self.scheduled_at.isoformat() if self.scheduled_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'created_at': self.created_at.isoformat()
        }
    
    def __repr__(self):
        return f'<Task {self.id}>'
EOF

cat > app/models/social_account.py << 'EOF'
from app import db
from datetime import datetime
import json

class SocialAccount(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False)
    platform = db.Column(db.String(32), nullable=False, index=True)  # twitter, instagram, etc.
    username = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(16), default='active', index=True)  # active, inactive, error
    auth_data = db.Column(db.Text, nullable=True)  # JSON con tokens y datos de autenticación (encriptado)
    last_used = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Estadísticas
    followers_count = db.Column(db.Integer, default=0)
    following_count = db.Column(db.Integer, default=0)
    posts_count = db.Column(db.Integer, default=0)
    last_stats_update = db.Column(db.DateTime, nullable=True)
    
    # Relaciones
    posts = db.relationship('SocialPost', backref='account', lazy=True, cascade='all, delete-orphan')
    
    def get_auth_data(self, 0,
               'El nombre de usuario debe comenzar con una letra y solo puede contener '
               'letras, números, puntos o guiones bajos.')
    ])
    email = StringField('Email', validators=[
        DataRequired(),
        Email(),
        Length(1, 120)
    ])
    password = PasswordField('Contraseña', validators=[
        DataRequired(),
        Length(8, 128),
        EqualTo('password2', message='Las contraseñas deben coincidir.')
    ])
    password2 = PasswordField('Confirmar contraseña', validators=[
        DataRequired()
    ])
    submit = SubmitField('Registrarse')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('El nombre de usuario ya está en uso.')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('El email ya está registrado.')


class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('Contraseña actual', validators=[
        DataRequired()
    ])
    password = PasswordField('Nueva contraseña', validators=[
        DataRequired(),
        Length(8, 128),
        EqualTo('password2', message='Las contraseñas deben coincidir.')
    ])
    password2 = PasswordField('Confirmar nueva contraseña', validators=[
        DataRequired()
    ])
    submit = SubmitField('Cambiar Contraseña')
EOF

cat > app/auth/routes.py << 'EOF'
from flask import render_template, redirect, request, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models.user import User
from app.auth import auth
from app.auth.forms import LoginForm, RegistrationForm, ChangePasswordForm
from datetime import datetime

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            user.last_login = datetime.utcnow()
            db.session.commit()
            next = request.args.get('next')
            if next is None or not next.startswith('/'):
                next = url_for('dashboard.index')
            return redirect(next)
        flash('Email o contraseña inválidos.', 'danger')
    
    return render_template('auth/login.html', form=form)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión.', 'success')
    return redirect(url_for('auth.login'))


@auth.route('/register', methods=['GET', 'POST'])
def register():
    # En producción, podría restringirse el registro solo a administradores
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data.lower(),
            password=form.password.data
        )
        db.session.add(user)
        db.session.commit()
        flash('¡Cuenta creada correctamente! Ahora puedes iniciar sesión.', 'success')
        return redirect(url_for('auth.login'))
        
    return render_template('auth/register.html', form=form)


@auth.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.old_password.data):
            current_user.password = form.password.data
            db.session.add(current_user)
            db.session.commit()
            flash('Tu contraseña ha sido actualizada.', 'success')
            return redirect(url_for('dashboard.profile'))
        else:
            flash('Contraseña actual incorrecta.', 'danger')
    return render_template('auth/change_password.html', form=form)
EOF

# Dashboard
cat > app/dashboard/__init__.py << 'EOF'
from flask import Blueprint

dashboard = Blueprint('dashboard', __name__)

from . import routes
EOF

cat > app/dashboard/routes.py << 'EOF'
from flask import render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from app import db
from app.dashboard import dashboard
from app.models.device import Device, DeviceLog
from app.models.task import Task
from app.models.social_account import SocialAccount, SocialPost
from datetime import datetime, timedelta
from sqlalchemy import func

@dashboard.route('/')
@login_required
def index():
    # Estadísticas generales
    devices_count = Device.query.count()
    active_devices_count = Device.query.filter(Device.status == 'online').count()
    tasks_count = Task.query.count()
    pending_tasks_count = Task.query.filter(Task.status == 'pending').count()
    running_tasks_count = Task.query.filter(Task.status == 'in_progress').count()
    completed_tasks_count = Task.query.filter(Task.status == 'completed').count()
    failed_tasks_count = Task.query.filter(Task.status == 'failed').count()
    social_accounts_count = SocialAccount.query.count()
    
    # Dispositivos recientes
    recent_devices = Device.query.order_by(Device.last_seen.desc()).limit(5).all()
    
    # Últimas tareas
    recent_tasks = Task.query.order_by(Task.created_at.desc()).limit(10).all()
    
    # Eventos recientes
    recent_logs = DeviceLog.query.order_by(DeviceLog.timestamp.desc()).limit(10).all()
    
    # Gráficos: tareas completadas por día (últimos 7 días)
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    tasks_by_day = db.session.query(
        func.date(Task.completed_at).label('date'),
        func.count(Task.id).label('count')
    ).filter(
        Task.status == 'completed',
        Task.completed_at >= seven_days_ago
    ).group_by(
        func.date(Task.completed_at)
    ).all()
    
    # Formatear datos para gráficos
    dates = [(seven_days_ago + timedelta(days=i)).strftime('%Y-%m-%d') for i in range(8)]
    tasks_chart_data = {date: 0 for date in dates}
    for date, count in tasks_by_day:
        if date.strftime('%Y-%m-%d') in tasks_chart_data:
            tasks_chart_data[date.strftime('%Y-%m-%d')] = count
    
    return render_template('dashboard/index.html',
                          devices_count=devices_count,
                          active_devices_count=active_devices_count,
                          tasks_count=tasks_count,
                          pending_tasks_count=pending_tasks_count,
                          running_tasks_count=running_tasks_count,
                          completed_tasks_count=completed_tasks_count,
                          failed_tasks_count=failed_tasks_count,
                          social_accounts_count=social_accounts_count,
                          recent_devices=recent_devices,
                          recent_tasks=recent_tasks,
                          recent_logs=recent_logs,
                          tasks_chart_data=tasks_chart_data)


@dashboard.route('/profile')
@login_required
def profile():
    return render_template('dashboard/profile.html')


@dashboard.route('/settings')
@login_required
def settings():
    return render_template('dashboard/settings.html')


@dashboard.route('/generate-api-key', methods=['POST'])
@login_required
def generate_api_key():
    current_user.generate_api_key()
    db.session.commit()
    return jsonify({'status': 'success', 'api_key': current_user.api_key})
EOF

# Inicialización de la API
cat > app/api/__init__.py << 'EOF'
from flask import Blueprint

api = Blueprint('api', __name__)

from . import devices, tasks, auth, social
EOF

# WebSocket
cat > app/websocket/__init__.py << 'EOF'
def register_handlers(socketio):
    """
    Registra los manejadores de eventos de websocket.
    Esta función se llama desde app/__init__.py
    """
    from . import handlers
EOF

cat > app/websocket/handlers.py << 'EOF'
from flask import request
from flask_socketio import emit, join_room, leave_room
from app import socketio, db
from app.models.device import Device, DeviceLog
from app.models.task import Task
from app.api.auth import validate_device_token
from datetime import datetime
import json

@socketio.on('connect')
def handle_connect():
    """Manejador de conexión inicial del cliente WebSocket"""
    client_type = request.args.get('client_type', 'web')
    
    if client_type == 'device':
        # Para dispositivos, verificar token de autenticación
        device_id = request.args.get('device_id')
        token = request.args.get('token')
        
        if not device_id or not token or not validate_device_token(device_id, token):
            return False  # Rechazar conexión
        
        # Verificar si el dispositivo existe
        device = Device.query.filter_by(device_id=device_id).first()
        if not device:
            return False  # Rechazar conexión
        
        # Actualizar estado del dispositivo
        device.status = 'online'
        device.last_seen = datetime.utcnow()
        db.session.commit()
        
        # Unirse a una sala específica para este dispositivo
        join_room(f'device_{device_id}')
        
        # Notificar a los clientes web
        emit('device_connected', device.to_dict(), broadcast=True, include_self=False)
        
        # Registrar log
        log = DeviceLog(
            device_id=device.id,
            level='info',
            message=f'Device connected via WebSocket: {device_id}'
        )
        db.session.add(log)
        db.session.commit()
    else:
        # Para clientes web u otros, unirse a la sala general
        join_room('web_clients')


@socketio.on('disconnect')
def handle_disconnect():
    """Manejador de desconexión del cliente WebSocket"""
    client_type = request.args.get('client_type', 'web')
    
    if client_type == 'device':
        device_id = request.args.get('device_id')
        if device_id:
            # Actualizar estado del dispositivo
            device = Device.query.filter_by(device_id=device_id).first()
            if device:
                device.status = 'offline'
                db.session.commit()
                
                # Notificar a los clientes web
                emit('device_disconnected', device.to_dict(), broadcast=True)
                
                # Registrar log
                log = DeviceLog(
                    device_id=device.id,
                    level='info',
                    message=f'Device disconnected from WebSocket: {device_id}'
                )
                db.session.add(log)
                db.session.commit()


@socketio.on('device_log')
def handle_device_log(data):
    """
    Recibe logs de dispositivos y los guarda en la base de datos.
    También los retransmite a los clientes web.
    """
    device_id = request.args.get('device_id')
    token = request.args.get('token')
    
    if not device_id or not token or not validate_device_token(device_id, token):
        return  # Ignorar mensajes no autorizados
    
    # Verificar si el dispositivo existe
    device = Device.query.filter_by(device_id=device_id).first()
    if not device:
        return  # Ignorar mensajes de dispositivos no registrados
    
    # Crear log
    log = DeviceLog(
        device_id=device.id,
        level=data.get('level', 'info'),
        message=data.get('message', '')
    )
    
    db.session.add(log)
    db.session.commit()
    
    # Retransmitir a los clientes web
    emit('device_log', log.to_dict(), room='web_clients')


@socketio.on('task_update')
def handle_task_update(data):
    """
    Recibe actualizaciones de tareas desde dispositivos.
    """
    device_id = request.args.get('device_id')
    token = request.args.get('token')
    
    if not device_id or not token or not validate_device_token(device_id, token):
        return  # Ignorar mensajes no autorizados
    
    # Verificar si el dispositivo existe
    device = Device.query.filter_by(device_id=device_id).first()
    if not device:
        return  # Ignorar mensajes de dispositivos no registrados
    
    task_id = data.get('task_id')
    if not task_id:
        return  # Ignorar mensajes sin ID de tarea
    
    # Verificar si la tarea existe
    task = Task.query.get(task_id)
    if not task or task.device_id != device.id:
        return  # Ignorar si la tarea no existe o no es de este dispositivo
    
    # Actualizar la tarea
    if 'status' in data:
        task.status = data['status']
    
    if 'result' in data:
        task.set_result(data['result'])
    
    if 'error_message' in data:
        task.error_message = data['error_message']
    
    if task.status == 'in_progress' and not task.started_at:
        task.started_at = datetime.utcnow()
    
    if task.status in ['completed', 'failed', 'cancelled'] and not task.completed_at:
        task.completed_at = datetime.utcnow()
    
    db.session.commit()
    
    # Retransmitir a los clientes web
    emit('task_update', task.to_dict(), room='web_clients')


@socketio.on('request_pending_tasks')
def handle_request_pending_tasks():
    """
    Maneja solicitudes de dispositivos para obtener sus tareas pendientes.
    """
    device_id = request.args.get('device_id')
    token = request.args.get('token')
    
    if not device_id or not token or not validate_device_token(device_id, token):
        return  # Ignorar mensajes no autorizados
    
    # Verificar si el dispositivo existe
    device = Device.query.filter_by(device_id=device_id).first()
    if not device:
        return  # Ignorar mensajes de dispositivos no registrados
    
    # Obtener tareas pendientes
    pending_tasks = Task.query.filter_by(device_id=device.id, status='pending')\
                              .filter((Task.scheduled_at == None) | (Task.scheduled_at <= datetime.utcnow()))\
                              .order_by(Task.priority.desc())\
                              .all()
    
    # Enviar tareas al dispositivo
    emit('pending_tasks', {
        'tasks': [task.to_dict() for task in pending_tasks]
    })
EOF

# Crear CSS personalizado
echo "Creando archivos CSS..."
mkdir -p app/static/css

cat > app/static/css/styles.css << 'EOF'
/* Estilos personalizados para BotFarm Panel */

/* Variables de colores */
:root {
    --primary-color: #2c3e50;
    --secondary-color: #34495e;
    --accent-color: #3498db;
    --success-color: #2ecc71;
    --warning-color: #f39c12;
    --danger-color: #e74c3c;
    --info-color: #3498db;
    --light-color: #f5f5f5;
    --dark-color: #2c3e50;
    --gray-color: #95a5a6;
}

/* Personalización general */
body {
    background-color: #f8f9fa;
    font-family: 'Roboto', 'Segoe UI', sans-serif;
    color: #333;
}

/* Navbar personalizada */
.navbar-dark {
    background-color: var(--primary-color) !important;
}

.navbar-dark .navbar-brand {
    font-weight: 700;
    color: white;
}

/* Tarjetas y sombras */
.card {
    border: none;
    border-radius: 8px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
    margin-bottom: 20px;
}

.card-header {
    background-color: rgba(0, 0, 0, 0.03);
    border-bottom: 1px solid rgba(0, 0, 0, 0.08);
    padding: 15px 20px;
}

.card-body {
    padding: 20px;
}

.shadow-sm {
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08) !important;
}

.shadow {
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.12) !important;
}

/* Botones personalizados */
.btn {
    border-radius: 6px;
    font-weight: 500;
}

.btn-primary {
    background-color: var(--accent-color);
    border-color: var(--accent-color);
}

.btn-primary:hover {
    background-color: #2980b9;
    border-color: #2980b9;
}

/* Estados de dispositivos y tareas */
.badge {
    font-weight: 500;
    padding: 6px 10px;
    border-radius: 4px;
}

/* Tabla con filas destacables */
.table-hover tbody tr:hover {
    background-color: rgba(52, 152, 219, 0.05);
}

.table th {
    font-weight: 600;
    color: #555;
}

/* Formularios */
.form-control, .form-select {
    border-radius: 6px;
    padding: 10px 15px;
    border: 1px solid #ddd;
}

.form-control:focus, .form-select:focus {
    border-color: var(--accent-color);
    box-shadow: 0 0 0 0.2rem rgba(52, 152, 219, 0.25);
}

/* Footer */
footer {
    margin-top: 50px;
    padding: 20px 0;
    background-color: var(--dark-color);
    color: #ecf0f1;
}

/* Iconos con colores */
.fa-power-off.text-success {
    color: var(--success-color) !important;
}

.fa-exclamation-triangle.text-danger {
    color: var(--danger-color) !important;
}

/* Notificaciones flotantes */
.toast {
    border: none;
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.12);
}

/* Mejora de listas */
.list-group-item {
    border-left: none;
    border-right: none;
    padding: 15px 20px;
}

.list-group-item:first-child {
    border-top: none;
}

.list-group-item:last-child {
    border-bottom: none;
}

/* Alertas y mensajes flash */
.alert {
    border: none;
    border-radius: 8px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
}

/* Pre y código */
pre {
    background-color: #f8f9fa;
    border-radius: 6px;
    padding: 15px;
    color: #333;
}

/* Paginación */
.pagination .page-item .page-link {
    border-radius: 4px;
    margin: 0 2px;
    color: var(--accent-color);
}

.pagination .page-item.active .page-link {
    background-color: var(--accent-color);
    border-color: var(--accent-color);
}

/* Animaciones para WebSocket updates */
@keyframes highlight {
    0% {
        background-color: rgba(52, 152, 219, 0.2);
    }
    100% {
        background-color: transparent;
    }
}

.highlight-update {
    animation: highlight 2s ease-out;
}

/* Media queries para responsividad */
@media (max-width: 768px) {
    .card-body {
        padding: 15px;
    }
    
    .table th, .table td {
        padding: 10px 8px;
    }
    
    .btn {
        padding: 6px 12px;
    }
}

/* Estilo para las pantallas de error */
.error-page {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 70vh;
    text-align: center;
}

.error-page h1 {
    font-size: 8rem;
    font-weight: 700;
    color: var(--accent-color);
    margin-bottom: 0;
}

.error-page p {
    font-size: 1.5rem;
    color: var(--gray-color);
    margin-bottom: 2rem;
}
EOF

# Crear plantillas HTML base
echo "Creando plantillas HTML base..."

# Plantilla principal (layout)
cat > app/templates/layout.html << 'EOF'
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}BotFarm - Panel de Control{% endblock %}</title>
    
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    
    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.3.0/css/all.min.css">
    
    <!-- Estilos propios -->
    <link rel="stylesheet" href="{{ url_for('static', filename='css/styles.css') }}">
    
    {% block styles %}{% endblock %}
</head>
<body>
    <!-- Barra de navegación -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="{{ url_for('dashboard.index') }}">
                <i class="fas fa-robot me-2"></i> BotFarm
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                {% if current_user.is_authenticated %}
                <ul class="navbar-nav me-auto">
                    <li class="nav-item">
                        <a class="nav-link {% if request.endpoint.startswith('dashboard.') %}active{% endif %}" href="{{ url_for('dashboard.index') }}">
                            <i class="fas fa-tachometer-alt me-1"></i> Dashboard
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link {% if request.endpoint.startswith('devices.') %}active{% endif %}" href="{{ url_for('devices.index') }}">
                            <i class="fas fa-mobile-alt me-1"></i> Dispositivos
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link {% if request.endpoint.startswith('tasks.') %}active{% endif %}" href="{{ url_for('tasks.index') }}">
                            <i class="fas fa-tasks me-1"></i> Tareas
                        </a>
                    </li>
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle {% if request.endpoint.startswith('social.') %}active{% endif %}" href="#" role="button" data-bs-toggle="dropdown">
                            <i class="fas fa-share-alt me-1"></i> Redes Sociales
                        </a>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="{{ url_for('social.accounts') }}">Cuentas</a></li>
                            <li><a class="dropdown-item" href="{{ url_for('social.posts') }}">Publicaciones</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="{{ url_for('social.generate_content') }}">Generar Contenido</a></li>
                        </ul>
                    </li>
                </ul>
                <ul class="navbar-nav">
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">
                            <i class="fas fa-user me-1"></i> {{ current_user.username }}
                        </a>
                        <ul class="dropdown-menu dropdown-menu-end">
                            <li><a class="dropdown-item" href="{{ url_for('dashboard.profile') }}">Perfil</a></li>
                            <li><a class="dropdown-item" href="{{ url_for('dashboard.settings') }}">Configuración</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="{{ url_for('auth.logout') }}">Cerrar Sesión</a></li>
                        </ul>
                    </li>
                </ul>
                {% else %}
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('auth.login') }}">Iniciar Sesión</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('auth.register') }}">Registrarse</a>
                    </li>
                </ul>
                {% endif %}
            </div>
        </div>
    </nav>
    
    <!-- Contenido principal -->
    <div class="container mt-4">
        <!-- Mensajes flash -->
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }} alert-dismissible fade show">
                        {{ message }}
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <!-- Contenido específico de la página -->
        {% block content %}{% endblock %}
    </div>
    
    <!-- Footer -->
    <footer class="bg-dark text-white mt-5 py-3">
        <div class="container text-center">
            <small>&copy; {{ now.year }} BotFarm - Sistema de Gestión de Bots Móviles</small>
        </div>
    </footer>
    
    <!-- Scripts -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/socket.io-client@4.6.1/dist/socket.io.min.js"></script>
    
    <!-- Script para WebSocket -->
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Conectar al servidor de WebSocket
            const socket = io();
            
            // Eventos de WebSocket
            socket.on('connect', function() {
                console.log('Conectado al servidor WebSocket');
            });
            
            socket.on('disconnect', function() {
                console.log('Desconectado del servidor WebSocket');
            });
            
            socket.on('device_update', function(data) {
                console.log('Actualización de dispositivo:', data);
                // Aquí se pueden actualizar elementos de la UI
            });
            
            socket.on('device_log', function(data) {
                console.log('Nuevo log de dispositivo:', data);
                // Actualizar registros de logs si están visibles
            });
            
            socket.on('task_update', function(data) {
                console.log('Actualización de tarea:', data);
                // Actualizar UI de tareas
            });
            
            // Exponer socket globalmente para que otras páginas puedan usarlo
            window.socket = socket;
        });
    </script>
    
    {% block scripts %}{% endblock %}
</body>
</html>
EOF

# Plantillas de error
cat > app/templates/404.html << 'EOF'
{% extends "layout.html" %}

{% block title %}404 - Página no encontrada{% endblock %}

{% block content %}
<div class="error-page">
    <h1>404</h1>
    <p>La página que estás buscando no existe.</p>
    <div>
        <a href="{{ url_for('dashboard.index') }}" class="btn btn-primary">
            <i class="fas fa-home me-1"></i> Volver al Dashboard
        </a>
    </div>
</div>
{% endblock %}
EOF

cat > app/templates/500.html << 'EOF'
{% extends "layout.html" %}

{% block title %}500 - Error del servidor{% endblock %}

{% block content %}
<div class="error-page">
    <h1>500</h1>
    <p>Ha ocurrido un error en el servidor.</p>
    <div>
        <a href="{{ url_for('dashboard.index') }}" class="btn btn-primary">
            <i class="fas fa-home me-1"></i> Volver al Dashboard
        </a>
        <button onclick="location.reload()" class="btn btn-outline-primary ms-2">
            <i class="fas fa-sync me-1"></i> Reintentar
        </button>
    </div>
</div>
{% endblock %}
EOF

# Plantillas de autenticación
cat > app/templates/auth/login.html << 'EOF'
{% extends "layout.html" %}

{% block title %}Iniciar Sesión - BotFarm{% endblock %}

{% block content %}
<div class="row justify-content-center">
    <div class="col-md-6">
        <div class="card shadow">
            <div class="card-header bg-primary text-white">
                <h4 class="mb-0"><i class="fas fa-sign-in-alt me-2"></i> Iniciar Sesión</h4>
            </div>
            <div class="card-body">
                <form method="POST" action="{{ url_for('auth.login') }}">
                    {{ form.csrf_token }}
                    
                    <div class="mb-3">
                        {{ form.email.label(class="form-label") }}
                        {{ form.email(class="form-control", placeholder="correo@ejemplo.com") }}
                        {% if form.email.errors %}
                            <div class="invalid-feedback d-block">
                                {% for error in form.email.errors %}
                                    {{ error }}
                                {% endfor %}
                            </div>
                        {% endif %}
                    </div>
                    
                    <div class="mb-3">
                        {{ form.password.label(class="form-label") }}
                        {{ form.password(class="form-control") }}
                        {% if form.password.errors %}
                            <div class="invalid-feedback d-block">
                                {% for error in form.password.errors %}
                                    {{ error }}
                                {% endfor %}
                            </div>
                        {% endif %}
                    </div>
                    
                    <div class="mb-3 form-check">
                        {{ form.remember_me(class="form-check-input") }}
                        {{ form.remember_me.label(class="form-check-label") }}
                    </div>
                    
                    <div class="d-grid gap-2">
                        {{ form.submit(class="btn btn-primary") }}
                    </div>
                </form>
            </div>
            <div class="card-footer text-center">
                <p class="mb-0">¿No tienes cuenta? <a href="{{ url_for('auth.register') }}">Regístrate</a></p>
            </div>
        </div>
    </div>
</div>
{% endblock %}
EOF

cat > app/templates/auth/register.html << 'EOF'
{% extends "layout.html" %}

{% block title %}Registrarse - BotFarm{% endblock %}

{% block content %}
<div class="row justify-content-center">
    <div class="col-md-6">
        <div class="card shadow">
            <div class="card-header bg-success text-white">
                <h4 class="mb-0"><i class="fas fa-user-plus me-2"></i> Crear Cuenta</h4>
            </div>
            <div class="card-body">
                <form method="POST" action="{{ url_for('auth.register') }}">
                    {{ form.csrf_token }}
                    
                    <div class="mb-3">
                        {{ form.username.label(class="form-label") }}
                        {{ form.username(class="form-control", placeholder="usuario") }}
                        {% if form.username.errors %}
                            <div class="invalid-feedback d-block">
                                {% for error in form.username.errors %}
                                    {{ error }}
                                {% endfor %}
                            </div>
                        {% endif %}
                    </div>
                    
                    <div class="mb-3">
                        {{ form.email.label(class="form-label") }}
                        {{ form.email(class="form-control", placeholder="correo@ejemplo.com") }}
                        {% if form.email.errors %}
                            <div class="invalid-feedback d-block">
                                {% for error in form.email.errors %}
                                    {{ error }}
                                {% endfor %}
                            </div>
                        {% endif %}
                    </div>
                    
                    <div class="mb-3">
                        {{ form.password.label(class="form-label") }}
                        {{ form.password(class="form-control") }}
                        {% if form.password.errors %}
                            <div class="invalid-feedback d-block">
                                {% for error in form.password.errors %}
                                    {{ error }}
                                {% endfor %}
                            </div>
                        {% endif %}
                    </div>
                    
                    <div class="mb-3">
                        {{ form.password2.label(class="form-label") }}
                        {{ form.password2(class="form-control") }}
                        {% if form.password2.errors %}
                            <div class="invalid-feedback d-block">
                                {% for error in form.password2.errors %}
                                    {{ error }}
                                {% endfor %}
                            </div>
                        {% endif %}
                    </div>
                    
                    <div class="d-grid gap-2">
                        {{ form.submit(class="btn btn-success") }}
                    </div>
                </form>
            </div>
            <div class="card-footer text-center">
                <p class="mb-0">¿Ya tienes cuenta? <a href="{{ url_for('auth.login') }}">Inicia Sesión</a></p>
            </div>
        </div>
    </div>
</div>
{% endblock %}
EOF

# Dashboard principal
mkdir -p app/templates/dashboard
cat > app/templates/dashboard/index.html << 'EOF'
{% extends "layout.html" %}

{% block title %}Dashboard - BotFarm{% endblock %}

{% block content %}
<h2 class="mb-4">Panel de Control</h2>

<!-- Tarjetas de estadísticas -->
<div class="row mb-4">
    <div class="col-md-3">
        <div class="card bg-primary text-white mb-3">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <h6 class="card-title">Dispositivos</h6>
                        <h2 class="mb-0">{{ devices_count }}</h2>
                    </div>
                    <div>
                        <i class="fas fa-mobile-alt fa-3x"></i>
                    </div>
                </div>
                <small>{{ active_devices_count }} activos</small>
            </div>
            <div class="card-footer bg-transparent">
                <a href="{{ url_for('devices.index') }}" class="text-white">Ver todos <i class="fas fa-arrow-right"></i></a>
            </div>
        </div>
    </div>
    
    <div class="col-md-3">
        <div class="card bg-success text-white mb-3">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <h6 class="card-title">Tareas</h6>
                        <h2 class="mb-0">{{ tasks_count }}</h2>
                    </div>
                    <div>
                        <i class="fas fa-tasks fa-3x"></i>
                    </div>
                </div>
                <small>{{ pending_tasks_count }} pendientes, {{ running_tasks_count }} en progreso</small>
            </div>
            <div class="card-footer bg-transparent">
                <a href="{{ url_for('tasks.index') }}" class="text-white">Ver todas <i class="fas fa-arrow-right"></i></a>
            </div>
        </div>
    </div>
    
    <div class="col-md-3">
        <div class="card bg-info text-white mb-3">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <h6 class="card-title">Completadas</h6>
                        <h2 class="mb-0">{{ completed_tasks_count }}</h2>
                    </div>
                    <div>
                        <i class="fas fa-check-circle fa-3x"></i>
                    </div>
                </div>
                <small>{{ failed_tasks_count }} fallidas</small>
            </div>
            <div class="card-footer bg-transparent">
                <a href="{{ url_for('tasks.index', status='completed') }}" class="text-white">Ver detalles <i class="fas fa-arrow-right"></i></a>
            </div>
        </div>
    </div>
    
    <div class="col-md-3">
        <div class="card bg-warning text-white mb-3">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <h6 class="card-title">Cuentas Sociales</h6>
                        <h2 class="mb-0">{{ social_accounts_count }}</h2>
                    </div>
                    <div>
                        <i class="fas fa-share-alt fa-3x"></i>
                    </div>
                </div>
                <small>Twitter, Instagram y más</small>
            </div>
            <div class="card-footer bg-transparent">
                <a href="{{ url_for('social.accounts') }}" class="text-white">Ver todas <i class="fas fa-arrow-right"></i></a>
            </div>
        </div>
    </div>
</div>

<div class="row">
    <!-- Gráfico de estadísticas -->
    <div class="col-md-8">
        <div class="card mb-4 shadow-sm">
            <div class="card-header">
                <h5 class="mb-0"><i class="fas fa-chart-line me-2"></i> Tareas Completadas (Últimos 7 días)</h5>
            </div>
            <div class="card-body">
                <canvas id="tasksChart" height="250"></canvas>
            </div>
        </div>
        
        <!-- Últimas Tareas -->
        <div class="card mb-4 shadow-sm">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5 class="mb-0"><i class="fas fa-tasks me-2"></i> Últimas Tareas</h5>
                <a href="{{ url_for('tasks.index') }}" class="btn btn-sm btn-primary">Ver Todas</a>
            </div>
            <div class="card-body p-0">
                <div class="table-responsive">
                    <table class="table table-hover mb-0">
                        <thead>
                            <tr>
                                <th>Nombre</th>
                                <th>Dispositivo</th>
                                <th>Tipo</th>
                                <th>Estado</th>
                                <th>Fecha</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for task in recent_tasks %}
                            <tr>
                                <td><a href="{{ url_for('tasks.detail', id=task.id) }}">{{ task.name }}</a></td>
                                <td>
                                    {% set device = task.device %}
                                    <a href="{{ url_for('devices.detail', id=device.id) }}">
                                        {{ device.name or device.device_id }}
                                    </a>
                                </td>
                                <td><span class="badge bg-secondary">{{ task.type }}</span></td>
                                <td>
                                    {% if task.status == 'pending' %}
                                    <span class="badge bg-warning">Pendiente</span>
                                    {% elif task.status == 'in_progress' %}
                                    <span class="badge bg-primary">En progreso</span>
                                    {% elif task.status == 'completed' %}
                                    <span class="badge bg-success">Completada</span>
                                    {% elif task.status == 'failed' %}
                                    <span class="badge bg-danger">Fallida</span>
                                    {% else %}
                                    <span class="badge bg-secondary">{{ task.status }}</span>
                                    {% endif %}
                                </td>
                                <td>{{ task.created_at.strftime('%d/%m/%Y %H:%M') }}</td>
                            </tr>
                            {% else %}
                            <tr>
                                <td colspan="5" class="text-center">No hay tareas recientes</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    
    <div class="col-md-4">
        <!-- Dispositivos recientes -->
        <div class="card mb-4 shadow-sm">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5 class="mb-0"><i class="fas fa-mobile-alt me-2"></i> Dispositivos Recientes</h5>
                <a href="{{ url_for('devices.index') }}" class="btn btn-sm btn-primary">Ver Todos</a>
            </div>
            <div class="card-body p-0">
                <div class="list-group list-group-flush">
                    {% for device in recent_devices %}
                    <a href="{{ url_for('devices.detail', id=device.id) }}" class="list-group-item list-group-item-action">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <h6 class="mb-1">{{ device.name or device.device_id }}</h6>
                                <small>{{ device.model or 'Modelo desconocido' }}</small>
                            </div>
                            <div>
                                {% if device.status == 'online' %}
                                <span class="badge bg-success">Online</span>
                                {% elif device.status == 'offline' %}
                                <span class="badge bg-secondary">Offline</span>
                                {% elif device.status == 'error' %}
                                <span class="badge bg-danger">Error</span>
                                {% else %}
                                <span class="badge bg-warning">{{ device.status }}</span>
                                {% endif %}
                            </div>
                        </div>
                        <small class="text-muted">Última vez: {{ device.last_seen.strftime('%d/%m/%Y %H:%M') }}</small>
                    </a>
                    {% else %}
                    <div class="list-group-item">
                        <p class="mb-0 text-center">No hay dispositivos recientes</p>
                    </div>
                    {% endfor %}
                </div>
            </div>
        </div>
        
        <!-- Últimos eventos -->
        <div class="card mb-4 shadow-sm">
            <div class="card-header">
                <h5 class="mb-0"><i class="fas fa-bell me-2"></i> Últimos Eventos</h5>
            </div>
            <div class="card-body p-0">
                <div class="list-group list-group-flush" id="recent-logs">
                    {% for log in recent_logs %}
                    <div class="list-group-item">
                        <div class="d-flex justify-content-between">
                            <span>{{ log.message | truncate(50) }}</span>
                            {% if log.level == 'info' %}
                            <span class="badge bg-info">info</span>
                            {% elif log.level == 'warning' %}
                            <span class="badge bg-warning">warning</span>
                            {% elif log.level == 'error' %}
                            <span class="badge bg-danger">error</span>
                            {% else %}
                            <span class="badge bg-secondary">{{ log.level }}</span>
                            {% endif %}
                        </div>
                        <small class="text-muted">{{ log.timestamp.strftime('%d/%m/%Y %H:%M:%S') }}</small>
                    </div>
                    {% else %}
                    <div class="list-group-item">
                        <p class="mb-0 text-center">No hay eventos recientes</p>
                    </div>
                    {% endfor %}
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
    // Gráfico de tareas
    const tasksChartCtx = document.getElementById('tasksChart').getContext('2d');
    const tasksChartData = {{ tasks_chart_data | tojson }};
    
    const labels = Object.keys(tasksChartData).sort();
    const data = labels.map(label => tasksChartData[label]);
    
    new Chart(tasksChartCtx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Tareas Completadas',
                data: data,
                backgroundColor: 'rgba(40, 167, 69, 0.2)',
                borderColor: 'rgba(40, 167, 69, 1)',
                borderWidth: 2,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0
                    }
                }
            }
        }
    });
    
    // WebSocket para actualizar logs en tiempo real
    document.addEventListener('DOMContentLoaded', function() {
        const recentLogsElement = document.getElementById('recent-logs');
        
        if (window.socket && recentLogsElement) {
            window.socket.on('device_log', function(log) {
                // Crear elemento para el nuevo log
                const logElement = document.createElement('div');
                logElement.className = 'list-group-item';
                
                // Definir clase de badge según el nivel
                let badgeClass = 'bg-secondary';
                if (log.level === 'info') badgeClass = 'bg-info';
                else if (log.level === 'warning') badgeClass = 'bg-warning';
                else if (log.level === 'error') badgeClass = 'bg-danger';
                
                // Formatear fecha
                const timestamp = new Date(log.timestamp);
                const formattedDate = timestamp.toLocaleDateString() + ' ' + timestamp.toLocaleTimeString();
                
                // Contenido del log
                logElement.innerHTML = `
                    <div class="d-flex justify-content-between">
                        <span>${log.message.substring(0, 50)}${log.message.length > 50 ? '...' : ''}</span>
                        <span class="badge ${badgeClass}">${log.level}</span>
                    </div>
                    <small class="text-muted">${formattedDate}</small>
                `;
                
                // Insertar al principio y mantener solo los últimos 10
                recentLogsElement.insertBefore(logElement, recentLogsElement.firstChild);
                if (recentLogsElement.children.length > 10) {
                    recentLogsElement.removeChild(recentLogsElement.lastChild);
                }
                
                // Si no había elementos, eliminar el mensaje "no hay eventos"
                if (recentLogsElement.querySelector('p.text-center')) {
                    recentLogsElement.innerHTML = '';
                    recentLogsElement.appendChild(logElement);
                }
            });
        }
    });
</script>
{% endblock %}
EOF

# Crear archivos vacíos para los módulos pendientes
mkdir -p app/templates/{devices,tasks,social}
touch app/devices/__init__.py
touch app/devices/routes.py
touch app/tasks/__init__.py
touch app/tasks/routes.py
touch app/social/__init__.py
touch app/social/routes.py
touch app/api/auth.py
touch app/api/devices.py
touch app/api/tasks.py
touch app/api/social.py

# Convertir el script en ejecutable
chmod +x run.py

echo "====== Generación de archivos completada ======"
echo "Para iniciar la aplicación:"
echo "1. Crea un entorno virtual: python -m venv venv"
echo "2. Activa el entorno: source venv/bin/activate  (En Windows: venv\\Scripts\\activate)"
echo "3. Instala las dependencias: pip install -r requirements.txt"
echo "4. Inicializa la base de datos: flask init-db"
echo "5. Inicia la aplicación: python run.py"
echo ""
echo "La aplicación estará disponible en http://localhost:5000"
EOF

# Hacerlo ejecutable
chmod +x generate_botfarm_panel.sh

# Explicación final
echo "Script generado como 'generate_botfarm_panel.sh'"
echo "Este script debe ejecutarse dentro del directorio 'server' del proyecto BotFarm."
echo "Para ejecutarlo:"
echo "1. Asegúrate de estar en la carpeta 'server' del proyecto"
echo "2. Ejecuta: chmod +x generate_botfarm_panel.sh"
echo "3. Ejecuta: ./generate_botfarm_panel.sh"
#!/bin/bash

# Script para generar la estructura de carpetas y archivos del Panel BotFarm
# Ejecutar este script dentro de la carpeta "server" del proyecto BotFarm

echo "====== Generando estructura de carpetas y archivos del Panel BotFarm ======"

# Crear la estructura de directorios
echo "Creando estructura de directorios..."

# Crear directorios principales
mkdir -p app/api
mkdir -p app/auth
mkdir -p app/dashboard
mkdir -p app/devices
mkdir -p app/models
mkdir -p app/social
mkdir -p app/tasks
mkdir -p app/templates/{auth,dashboard,devices,social,tasks}
mkdir -p app/static/{css,js,img,uploads}
mkdir -p app/websocket

# Crear archivos de inicialización
echo "Creando archivos de inicialización Python..."

# Crear archivos __init__.py
touch app/__init__.py
touch app/api/__init__.py
touch app/auth/__init__.py
touch app/dashboard/__init__.py
touch app/devices/__init__.py
touch app/models/__init__.py
touch app/social/__init__.py
touch app/tasks/__init__.py
touch app/websocket/__init__.py

# Crear archivos principales
echo "Creando archivos principales..."

# Archivos de configuración y ejecución
cat > config.py << 'EOF'
import os
from datetime import timedelta

class Config:
    # Configuración básica
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev_key_change_in_production')
    DEBUG = False
    TESTING = False
    
    # Configuración de la base de datos
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///botfarm.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Configuración de sesión
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)
    
    # Configuración de OpenAI
    OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY')
    
    # Configuración de WebSocket
    SOCKETIO_PING_TIMEOUT = 10
    SOCKETIO_PING_INTERVAL = 5
    
    # Configuración de upload
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'app/static/uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB máximo

class DevelopmentConfig(Config):
    DEBUG = True
    
class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    
class ProductionConfig(Config):
    # En producción, asegúrate de tener estas variables configuradas
    DEBUG = False
    
    # Configuración de seguridad adicional
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_HTTPONLY = True

# Diccionario de configuraciones
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
EOF

cat > wsgi.py << 'EOF'
from app import create_app, socketio

app = create_app('production')

if __name__ == '__main__':
    socketio.run(app)
EOF

cat > run.py << 'EOF'
#!/usr/bin/env python
from app import create_app, socketio, db
from app.models.user import User
from app.models.device import Device, DeviceLog
from app.models.task import Task
from app.models.social_account import SocialAccount, SocialPost
from datetime import datetime, timedelta
import os
import click
import json

app = create_app('development')

@app.shell_context_processor
def make_shell_context():
    return dict(
        app=app, db=db, 
        User=User, Device=Device, DeviceLog=DeviceLog,
        Task=Task, SocialAccount=SocialAccount, 
        SocialPost=SocialPost
    )

@app.cli.command("create-admin")
@click.argument("username")
@click.argument("email")
@click.argument("password")
def create_admin(username, email, password):
    """Crea un usuario administrador"""
    if User.query.filter_by(username=username).first():
        click.echo(f"Usuario {username} ya existe.")
        return
    
    if User.query.filter_by(email=email).first():
        click.echo(f"Email {email} ya está registrado.")
        return
    
    user = User(username=username, email=email, is_admin=True)
    user.password = password
    db.session.add(user)
    db.session.commit()
    click.echo(f"Usuario administrador {username} creado correctamente.")

@app.cli.command("init-db")
def init_db():
    """Inicializa la base de datos con datos de ejemplo"""
    # Eliminar datos existentes
    db.drop_all()
    db.create_all()
    
    # Crear usuario admin
    admin = User(
        username="admin",
        email="admin@example.com",
        is_admin=True
    )
    admin.password = "admin123"
    db.session.add(admin)
    
    # Crear algunos dispositivos de ejemplo
    devices = [
        Device(
            device_id="device_1",
            name="Dispositivo 1",
            status="online",
            model="Samsung Galaxy S10",
            android_version="11",
            battery_level=85,
            ip_address="192.168.1.100",
            last_seen=datetime.utcnow()
        ),
        Device(
            device_id="device_2",
            name="Dispositivo 2",
            status="offline",
            model="Xiaomi Redmi Note 9",
            android_version="10",
            battery_level=45,
            last_seen=datetime.utcnow() - timedelta(hours=5)
        ),
        Device(
            device_id="device_3",
            name="Dispositivo 3",
            status="error",
            model="Google Pixel 4",
            android_version="12",
            battery_level=12,
            last_seen=datetime.utcnow() - timedelta(minutes=30)
        )
    ]
    
    for device in devices:
        db.session.add(device)
    
    # Crear tareas de ejemplo
    tasks = [
        Task(
            device_id=1,
            name="Publicar en Twitter",
            type="social_post",
            status="completed",
            priority=5,
            scheduled_at=datetime.utcnow() - timedelta(hours=2),
            started_at=datetime.utcnow() - timedelta(hours=2),
            completed_at=datetime.utcnow() - timedelta(hours=1, minutes=55)
        ),
        Task(
            device_id=1,
            name="Recopilar datos de Instagram",
            type="data_scraping",
            status="in_progress",
            priority=3,
            started_at=datetime.utcnow() - timedelta(minutes=15)
        ),
        Task(
            device_id=2,
            name="Reiniciar dispositivo",
            type="system",
            status="pending",
            priority=10,
            scheduled_at=datetime.utcnow() + timedelta(hours=1)
        ),
        Task(
            device_id=3,
            name="Actualizar firmware",
            type="system",
            status="failed",
            priority=8,
            started_at=datetime.utcnow() - timedelta(hours=1),
            completed_at=datetime.utcnow() - timedelta(minutes=50),
            error_message="No se pudo acceder al servidor de actualización"
        )
    ]
    
    for task in tasks:
        db.session.add(task)
    
    # Configurar parámetros para las tareas
    tasks[0].set_parameters({
        "platform": "twitter",
        "content": "¡Hola mundo desde BotFarm! #automatización #bots",
        "media_urls": []
    })
    
    tasks[0].set_result({
        "success": True,
        "post_id": "1234567890",
        "url": "https://twitter.com/user/status/1234567890"
    })
    
    tasks[1].set_parameters({
        "platform": "instagram",
        "username": "target_user",
        "data_type": "followers",
        "max_items": 100
    })
    
    tasks[2].set_parameters({
        "command": "restart",
        "delay": 0
    })
    
    tasks[3].set_parameters({
        "firmware_version": "2.0.1",
        "force_update": True
    })
    
    # Crear cuentas sociales de ejemplo
    accounts = [
        SocialAccount(
            device_id=1,
            platform="twitter",
            username="bot_user1",
            status="active",
            followers_count=250,
            following_count=100,
            posts_count=75,
            last_used=datetime.utcnow() - timedelta(hours=2),
            last_stats_update=datetime.utcnow() - timedelta(hours=12)
        ),
        SocialAccount(
            device_id=1,
            platform="instagram",
            username="bot_insta",
            status="active",
            followers_count=520,
            following_count=300,
            posts_count=45,
            last_used=datetime.utcnow() - timedelta(days=1),
            last_stats_update=datetime.utcnow() - timedelta(days=1)
        ),
        SocialAccount(
            device_id=2,
            platform="facebook",
            username="bot_fb_user",
            status="inactive",
            followers_count=0,
            following_count=0,
            posts_count=0
        )
    ]
    
    for account in accounts:
        db.session.add(account)
    
    # Configurar datos de autenticación para las cuentas
    accounts[0].set_auth_data({
        "api_key": "dummy_api_key_1",
        "api_secret": "dummy_api_secret_1",
        "access_token": "dummy_access_token_1",
        "access_secret": "dummy_access_secret_1"
    })
    
    accounts[1].set_auth_data({
        "username": "bot_insta",
        "password": "dummy_password",
        "auth_token": "dummy_auth_token_2"
    })
    
    # Crear publicaciones de ejemplo
    posts = [
        SocialPost(
            account_id=1,
            platform="twitter",
            post_id="1234567890",
            content="¡Hola mundo desde BotFarm! #automatización #bots",
            status="published",
            published_at=datetime.utcnow() - timedelta(hours=2),
            likes_count=15,
            comments_count=3,
            shares_count=5
        ),
        SocialPost(
            account_id=2,
            platform="instagram",
            content="Automatizando con BotFarm #tech #automation",
            media_urls=json.dumps(["/static/uploads/example_image.jpg"]),
            status="draft"
        )
    ]
    
    for post in posts:
        db.session.add(post)
    
    # Crear logs de ejemplo
    logs = [
        DeviceLog(
            device_id=1,
            level="info",
            message="Dispositivo iniciado correctamente",
            timestamp=datetime.utcnow() - timedelta(hours=5)
        ),
        DeviceLog(
            device_id=1,
            level="info",
            message="Tarea de publicación en Twitter completada",
            timestamp=datetime.utcnow() - timedelta(hours=1, minutes=55)
        ),
        DeviceLog(
            device_id=2,
            level="warning",
            message="Batería baja (20%)",
            timestamp=datetime.utcnow() - timedelta(hours=3)
        ),
        DeviceLog(
            device_id=3,
            level="error",
            message="Error al actualizar firmware: No se pudo acceder al servidor",
            timestamp=datetime.utcnow() - timedelta(minutes=50)
        )
    ]
    
    for log in logs:
        db.session.add(log)
    
    # Guardar todos los cambios
    db.session.commit()
    
    click.echo("Base de datos inicializada con datos de ejemplo.")

if __name__ == '__main__':
    # Asegurarse de que la carpeta de uploads exista
    uploads_dir = os.path.join(app.static_folder, 'uploads')
    if not os.path.exists(uploads_dir):
        os.makedirs(uploads_dir)
    
    # Ejecutar la aplicación con WebSocket
    socketio.run(app, debug=app.config['DEBUG'], host='0.0.0.0')
EOF

cat > requirements.txt << 'EOF'
Flask==2.2.3
Flask-SQLAlchemy==3.0.3
Flask-Migrate==4.0.4
Flask-Login==0.6.2
Flask-WTF==1.1.1
Flask-SocketIO==5.3.3
python-dotenv==1.0.0
gunicorn==20.1.0
eventlet==0.33.3
psycopg2-binary==2.9.6
redis==4.5.4
openai==0.27.6
requests==2.29.0
pytz==2023.3
cryptography==40.0.2
email_validator==2.0.0
WTForms==3.0.1
SQLAlchemy==2.0.10
Werkzeug==2.2.3
itsdangerous==2.1.2
Jinja2==3.1.2
MarkupSafe==2.1.2
EOF

cat > README.md << 'EOF'
# BotFarm - Panel de Control

Panel de administración web para la gestión de bots móviles Android. Este panel permite controlar múltiples dispositivos, programar tareas, gestionar cuentas de redes sociales y monitorear la actividad de los bots.

## Características

- **Gestión de Dispositivos**: Monitoreo en tiempo real de dispositivos Android
- **Tareas Programadas**: Creación y seguimiento de tareas para los dispositivos
- **Cuentas de Redes Sociales**: Administración de cuentas de Twitter, Instagram y otras plataformas
- **Publicaciones**: Programación y seguimiento de publicaciones en redes sociales
- **Generación de Contenido**: Integración con OpenAI para generar contenido
- **WebSockets**: Comunicación en tiempo real entre el servidor y los dispositivos

## Requisitos

- Python 3.8+
- PostgreSQL
- Redis (para WebSockets)
- Cuenta en OpenAI (opcional, para generación de contenido)

## Instalación

1. Clonar el repositorio:
```bash
git clone https://github.com/tuusuario/botfarm-panel.git
cd botfarm-panel
```

2. Crear y activar un entorno virtual:
```bash
python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate
```

3. Instalar las dependencias:
```bash
pip install -r requirements.txt
```

4. Configurar las variables de entorno:
```bash
cp .env.example .env
# Editar .env con los valores adecuados
```

5. Inicializar la base de datos:
```bash
flask init-db
```

6. Crear un usuario administrador:
```bash
flask create-admin admin admin@example.com password123
```

## Ejecución

Para desarrollo:
```bash
python run.py
```

Para producción, se recomienda usar Gunicorn con Eventlet:
```bash
gunicorn -k eventlet -w 1 --bind 0.0.0.0:5000 wsgi:app
```

## Estructura del Proyecto

```
botfarm-panel/
├── app/                  # Aplicación principal
│   ├── api/              # API REST
│   ├── auth/             # Autenticación
│   ├── dashboard/        # Panel principal
│   ├── devices/          # Gestión de dispositivos
│   ├── models/           # Modelos de base de datos
│   ├── social/           # Redes sociales
│   ├── tasks/            # Gestión de tareas
│   ├── templates/        # Plantillas HTML
│   ├── static/           # Archivos estáticos
│   └── websocket/        # Manejadores de WebSocket
├── config.py             # Configuración
├── requirements.txt      # Dependencias
├── run.py                # Script para ejecutar en desarrollo
└── wsgi.py               # Punto de entrada para producción
```

## Uso con la App Android

Para que los dispositivos se conecten al panel, deben tener instalada la aplicación BotFarm para Android. La aplicación se configura con la URL del panel y se registra automáticamente.

## Seguridad

El panel utiliza:
- Autenticación de usuarios con Flask-Login
- Tokens CSRF para prevenir ataques CSRF
- Validación de datos de entrada
- Cifrado de datos sensibles (tokens de API, contraseñas, etc.)
- Conexiones seguras mediante WebSockets

## Licencia

Este proyecto está licenciado bajo la Licencia MIT. Consulte el archivo LICENSE para más detalles.

## Contribuciones

Las contribuciones son bienvenidas. Por favor, abra un issue o envíe un pull request para colaborar.
EOF

# Crear archivos de la aplicación principal
cat > app/__init__.py << 'EOF'
from flask import Flask, render_template
from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from config import config
import os

# Inicializar extensiones
db = SQLAlchemy()
migrate = Migrate()
socketio = SocketIO()
login_manager = LoginManager()
csrf = CSRFProtect()

def create_app(config_name='default'):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    
    # Asegurar que existe el directorio de uploads
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    
    # Inicializar extensiones con la app
    db.init_app(app)
    migrate.init_app(app, db)
    socketio.init_app(app, cors_allowed_origins="*", async_mode='eventlet')
    login_manager.init_app(app)
    csrf.init_app(app)
    
    # Configurar login
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Por favor inicia sesión para acceder a esta página.'
    
    # Registrar blueprints
    from app.api import api as api_blueprint
    app.register_blueprint(api_blueprint, url_prefix='/api')
    
    from app.auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/auth')
    
    from app.dashboard import dashboard as dashboard_blueprint
    app.register_blueprint(dashboard_blueprint)
    
    from app.devices import devices as devices_blueprint
    app.register_blueprint(devices_blueprint, url_prefix='/devices')
    
    from app.tasks import tasks as tasks_blueprint
    app.register_blueprint(tasks_blueprint, url_prefix='/tasks')
    
    from app.social import social as social_blueprint
    app.register_blueprint(social_blueprint, url_prefix='/social')
    
    from app.websocket import register_handlers
    register_handlers(socketio)
    
    # Manejador de errores 404
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('404.html'), 404
    
    # Manejador de errores 500
    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template('500.html'), 500
    
    return app
EOF

# Crear modelos
echo "Creando modelos de datos..."

cat > app/models/user.py << 'EOF'
from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import uuid

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    api_key = db.Column(db.String(64), unique=True, index=True, nullable=True)
    last_login = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.api_key is None:
            self.api_key = str(uuid.uuid4())
    
    @property
    def password(self):
        raise AttributeError('La contraseña no es un atributo legible')
    
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def generate_api_key(self):
        self.api_key = str(uuid.uuid4())
        return self.api_key
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'is_admin': self.is_admin,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'created_at': self.created_at.isoformat()
        }
    
    def __repr__(self):
        return f'<User {self.username}>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
EOF

cat > app/models/device.py << 'EOF'
from app import db
from datetime import datetime

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    name = db.Column(db.String(64), nullable=True)
    status = db.Column(db.String(16), default='offline', index=True)  # online, offline, error
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    model = db.Column(db.String(64), nullable=True)
    android_version = db.Column(db.String(32), nullable=True)
    battery_level = db.Column(db.Integer, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relaciones
    tasks = db.relationship('Task', backref='device', lazy=True, cascade='all, delete-orphan')
    social_accounts = db.relationship('SocialAccount', backref='device', lazy=True, cascade='all, delete-orphan')
    logs = db.relationship('DeviceLog', backref='device', lazy=True, cascade='all, delete-orphan')
    
    def is_active(self):
        """Comprueba si el dispositivo está activo (visto en los últimos 5 minutos)"""
        if not self.last_seen:
            return False
        delta = datetime.utcnow() - self.last_seen
        return delta.total_seconds() < 300  # 5 minutos
    
    def to_dict(self):
        return {
            'id': self.id,
            'device_id': self.device_id,
            'name': self.name,
            'status': self.status,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'model': self.model,
            'android_version': self.android_version,
            'battery_level': self.battery_level,
            'ip_address': self.ip_address,
            'is_active': self.is_active(),
            'created_at': self.created_at.isoformat(),
            'social_accounts_count': len(self.social_accounts),
            'tasks_count': len(self.tasks)
        }
    
    def __repr__(self):
        return f'<Device {self.device_id}>'


class DeviceLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    level = db.Column(db.String(10), default='info', index=True)  # info, warning, error
    message = db.Column(db.Text, nullable=False)
    
    def to_dict(self):
        return {
            'id': self.id,
            'device_id': self.device_id,
            'timestamp': self.timestamp.isoformat(),
            'level': self.level,
            'message': self.message
        }
    
    def __repr__(self):
        return f'<DeviceLog {self.id}>'
EOF

cat > app/models/task.py << 'EOF'
from app import db
from datetime import datetime
import json

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False, index=True)
    name = db.Column(db.String(64), nullable=False)
    type = db.Column(db.String(32), nullable=False, index=True)  # social_post, data_scraping, etc.
    status = db.Column(db.String(16), default='pending', index=True)  # pending, in_progress, completed, failed
    priority = db.Column(db.Integer, default=0, index=True)  # Mayor número = mayor prioridad
    parameters = db.Column(db.Text, nullable=True)  # JSON con parámetros
    result = db.Column(db.Text, nullable=True)  # JSON con resultado
    error_message = db.Column(db.Text, nullable=True)
    scheduled_at = db.Column(db.DateTime, nullable=True, index=True)
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    def get_parameters(self):
        """Convierte el texto JSON de parámetros a diccionario"""
        if not self.parameters:
            return {}
        try:
            return json.loads(self.parameters)
        except json.JSONDecodeError:
            return {}
    
    def set_parameters(self, params_dict):
        """Convierte un diccionario a texto JSON para parámetros"""
        if params_dict:
            self.parameters = json.dumps(params_dict)
        else:
            self.parameters = None
    
    def get_result(self):
        """Convierte el texto JSON de resultado a diccionario"""
        if not self.result:
            return {}
        try:
            return json.loads(self.result)
        except json.JSONDecodeError:
            return {}
    
    def set_result(self, result_dict):
        """Convierte un diccionario a texto JSON para resultado"""
        if result_dict:
            self.result = json.dumps(result_dict)
        else:
            self.result = None
    
    def to_dict(self):
        return {
            'id': self.id,
            'device_id': self.device_id,
            'name': self.name,
            'type': self.type,
            'status': self.status,
            'priority': self.priority,
            'parameters': self.get_parameters(),
            'result': self.get_result(),
            'error_message': self.error_message,
            'scheduled_at': self.scheduled_at.isoformat() if self.scheduled_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'created_at': self.created_at.isoformat()
        }
    
    def __repr__(self):
        return f'<Task {self.id}>'
EOF

cat > app/models/social_account.py << 'EOF'
from app import db
from datetime import datetime
import json

class SocialAccount(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False)
    platform = db.Column(db.String(32), nullable=False, index=True)  # twitter, instagram, etc.
    username = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(16), default='active', index=True)  # active, inactive, error
    auth_data = db.Column(db.Text, nullable=True)  # JSON con tokens y datos de autenticación (encriptado)
    last_used = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Estadísticas
    followers_count = db.Column(db.Integer, default=0)
    following_count = db.Column(db.Integer, default=0)
    posts_count = db.Column(db.Integer, default=0)
    last_stats_update = db.Column(db.DateTime, nullable=True)
    
    # Relaciones
    posts = db.relationship('SocialPost', backref='account', lazy=True, cascade='all, delete-orphan')
    
    def get_auth_data(self