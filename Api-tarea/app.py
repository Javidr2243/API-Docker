from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from cryptography.fernet import Fernet
import uuid
import time

app = Flask(__name__)

SECRET_KEY = "una_clave_secreta_muy_segura"
serializer = URLSafeTimedSerializer(SECRET_KEY)
cipher_suite = Fernet(Fernet.generate_key())
deactivated_tokens = set()


@app.route('/')
def hello_world():
    return "Hola mundo, el API está funcionando."


@app.route('/crear-token', methods=['POST'])
def create_token():
    unique_id = str(uuid.uuid4())

    token = serializer.dumps({'uuid': unique_id}, salt='token_salt_crearrrr')
    return jsonify({'token': token})


@app.route('/validar-token', methods=['POST'])
def validate_token():
    token = request.json.get('token')
    if not token:
        return jsonify({'error': 'Token requerido'}), 400

    try:
        data = serializer.loads(
            token, salt='token_salt_crearrrr', max_age=3600)
        return jsonify({'mensaje': 'Token válido'}), 200
    except SignatureExpired:
        return jsonify({'error': 'Token expirado'}), 401
    except BadSignature:
        return jsonify({'error': 'Token inválido'}), 401


@app.route('/desactivar-token', methods=['POST'])
def deactivate_token():
    token = request.json.get('token')
    if not token:
        return jsonify({'error': 'No se ingresó el token'}), 400

    if token in deactivated_tokens:
        return jsonify({'error': 'Token ya está desactivado'}), 400

    try:
        serializer.loads(token, salt='token_salt_crearrrr', max_age=3600)
        deactivated_tokens.add(token)
        return jsonify({'mensaje': 'Token desactivado'})
    except SignatureExpired:
        return jsonify({'error': 'Token expirado'}), 401
    except BadSignature:
        return jsonify({'error': 'Token inválido'}), 401


@app.route('/encriptar-mensaje', methods=['POST'])
def encrypt_message():
    token = request.json.get('token')
    message = request.json.get('mensaje')
    if not token or not message:
        return jsonify({'error': 'Token y mensaje requeridos'}), 400

    if token in deactivated_tokens:
        return jsonify({'error': 'Token desactivado'}), 401

    try:
        serializer.loads(token, salt='token_salt_crearrrr', max_age=3600)
        encrypted_message = cipher_suite.encrypt(message.encode())
        return jsonify({'mensaje_encriptado': encrypted_message.decode()})
    except SignatureExpired:
        return jsonify({'error': 'Token expirado'}), 401
    except BadSignature:
        return jsonify({'error': 'Token inválido'}), 401


@app.route('/desencriptar-mensaje', methods=['POST'])
def decrypt_message():
    token = request.json.get('token')
    encrypted_message = request.json.get('mensaje')
    if not token or not encrypted_message:
        return jsonify({'error': 'Token y mensaje encriptado requeridos'}), 400

    if token in deactivated_tokens:
        return jsonify({'error': 'Token desactivado'}), 401

    try:
        serializer.loads(token, salt='token_salt_crearrrr', max_age=3600)
        decrypted_message = cipher_suite.decrypt(encrypted_message.encode())
        return jsonify({'mensaje_desencriptado': decrypted_message.decode()})
    except SignatureExpired:
        return jsonify({'error': 'Token expirado'}), 401
    except BadSignature:
        return jsonify({'error': 'Token inválido'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)
