#!/bin/bash
# Script para generar un keystore y firmar la APK de Android

# Variables de configuración
APP_NAME="BotFarmEdu"
KEYSTORE_FILE="botfarm.keystore"
KEY_ALIAS="botfarm"
APK_FILE="app/build/outputs/apk/release/app-release-unsigned.apk"
SIGNED_APK="app/build/outputs/apk/release/botfarm-release.apk"

# Generar keystore
echo "Generando keystore para firmar la APK..."
keytool -genkey -v -keystore $KEYSTORE_FILE -alias $KEY_ALIAS -keyalg RSA -keysize 2048 -validity 10000 \
    -dname "CN=YourCompany, OU=Development, O=YourOrganization, L=YourCity, ST=YourState, C=YourCountry"

# Solicitar contraseña para el keystore (o establecerla en una variable)
echo "Por favor, introduzca la contraseña del keystore:"
read -s KEYSTORE_PASSWORD

# Construir la APK en modo release
echo "Construyendo APK en modo release..."
./gradlew assembleRelease

# Firmar la APK
echo "Firmando la APK..."
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore $KEYSTORE_FILE \
    -storepass $KEYSTORE_PASSWORD $APK_FILE $KEY_ALIAS

# Alinear la APK (optimización)
echo "Alineando la APK para optimizar su tamaño..."
zipalign -v 4 $APK_FILE $SIGNED_APK

# Verificar la firma
echo "Verificando la firma de la APK..."
jarsigner -verify -verbose -certs $SIGNED_APK

echo "===================================="
echo "Proceso de firma completado!"
echo "APK firmada disponible en: $SIGNED_APK"
echo "===================================="
