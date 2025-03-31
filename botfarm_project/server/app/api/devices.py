from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required
from app import db
from app.models.device import Device
from datetime import datetime

devices_api = Blueprint('devices_api', __name__)

@devices_api.route('/devices', methods=['GET'])
@login_required
def get_devices():
    """
    Obtiene la lista de dispositivos.
    """
    devices = Device.query.all()
    return jsonify({
        'status': 'success',
        'devices': [device.to_dict() for device in devices]
    })

@devices_api.route('/devices/<device_id>', methods=['GET'])
@login_required
def get_device(device_id):
    """
    Obtiene información detallada de un dispositivo.
    """
    device = Device.query.filter_by(device_id=device_id).first()
    
    if not device:
        return jsonify({
            'status': 'error',
            'message': f'Dispositivo no encontrado: {device_id}'
        }), 404
    
    return jsonify({
        'status': 'success',
        'device': device.to_dict()
    })

@devices_api.route('/devices', methods=['POST'])
@login_required
def create_device():
    """
    Crea o actualiza un dispositivo.
    """
    data = request.json
    
    # Verificar parámetros obligatorios
    if 'device_id' not in data:
        return jsonify({
            'status': 'error',
            'message': 'Falta el parámetro obligatorio: device_id'
        }), 400
    
    # Verificar si el dispositivo ya existe
    device = Device.query.filter_by(device_id=data['device_id']).first()
    created = False
    
    if not device:
        # Crear nuevo dispositivo
        device = Device(device_id=data['device_id'])
        created = True
    
    # Actualizar propiedades
    if 'name' in data:
        device.name = data['name']
    
    if 'status' in data:
        device.status = data['status']
    
    device.last_seen = datetime.utcnow()
    
    # Guardar en la base de datos
    db.session.add(device)
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'device': device.to_dict(),
        'created': created
    })
