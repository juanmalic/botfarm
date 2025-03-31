# BotFarm - Sistema de Gestión de Bots Móviles para Android

Este proyecto implementa un sistema completo para gestionar una granja de bots móviles Android con fines educativos. El sistema consta de una aplicación Android para ejecutar en cada dispositivo y un panel de control web desarrollado en Flask.

## Características Principales

- Gestión centralizada de múltiples dispositivos Android
- Automatización de interacciones en redes sociales (Twitter e Instagram)
- Generación de contenido utilizando la API de OpenAI
- Programación de tareas y acciones
- Panel de control web para monitoreo y gestión

## Estructura del Proyecto

- `/android`: Aplicación Android para ejecutar en cada dispositivo
- `/server`: Servidor web Flask para el panel de control
- `/scripts`: Scripts de utilidad para despliegue y construcción
- `/docs`: Documentación detallada del proyecto

## Requisitos

### Para la aplicación Android:
- Android 6.0 (API 23) o superior
- Conexión a Internet

### Para el servidor:
- Python 3.8 o superior
- PostgreSQL
- Redis
- Nginx
- Cuenta en OpenAI (para la generación de contenido)

## Guía Rápida

### 1. Configuración del Servidor

```bash
cd scripts/deploy
./server_setup.sh
```

### 2. Compilar la Aplicación Android

```bash
cd android
./gradlew assembleRelease
```

### 3. Firmar la APK

```bash
cd scripts/build
./sign_apk.sh
```

### 4. Instalar en Dispositivos

Distribuye la APK firmada a los dispositivos que formarán parte de la granja.

## Documentación

Para más detalles, consulta la documentación completa en la carpeta `/docs`.

## Licencia

Este proyecto está licenciado bajo [MIT License](LICENSE).

## Aviso legal

Este proyecto es solo para fines educativos. Asegúrate de cumplir con los términos de servicio de las plataformas de redes sociales correspondientes.
