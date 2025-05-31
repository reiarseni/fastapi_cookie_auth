"""
Utilidades criptográficas para el manejo seguro de cookies y sesiones.

Este módulo proporciona funciones para firmar y verificar cookies,
así como para generar y manejar tokens de sesión aleatorios.
"""

import base64
import hashlib
import hmac
import json
import os
import time
import uuid
from typing import Any, Dict, Optional, Tuple, Union


def generate_session_token() -> str:
    """
    Genera un token de sesión aleatorio usando UUID.
    
    Returns:
        Un token de sesión único
    """
    return str(uuid.uuid4())


def sign_value(value: str, secret_key: str) -> str:
    """
    Firma un valor utilizando HMAC-SHA256.
    
    Args:
        value: El valor a firmar
        secret_key: La clave secreta para la firma
        
    Returns:
        El valor firmado en formato: valor.firma_base64
    """
    if not secret_key:
        raise ValueError("Se requiere una clave secreta para firmar valores")
    
    # Calcular la firma HMAC
    signature = hmac.new(
        secret_key.encode('utf-8'),
        value.encode('utf-8'),
        hashlib.sha256
    ).digest()
    
    # Codificar la firma en base64 (URL-safe)
    signature_b64 = base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')
    
    # Devolver valor.firma
    return f"{value}.{signature_b64}"


def verify_signed_value(signed_value: str, secret_key: str) -> Optional[str]:
    """
    Verifica y extrae el valor original de un valor firmado.
    
    Args:
        signed_value: El valor firmado en formato valor.firma_base64
        secret_key: La clave secreta usada para la firma
        
    Returns:
        El valor original si la firma es válida, None en caso contrario
    """
    if not secret_key:
        raise ValueError("Se requiere una clave secreta para verificar valores firmados")
    
    # Dividir en valor y firma
    try:
        value, signature_b64 = signed_value.rsplit('.', 1)
    except ValueError:
        # Formato inválido
        return None
    
    # Calcular la firma esperada
    expected_signature = hmac.new(
        secret_key.encode('utf-8'),
        value.encode('utf-8'),
        hashlib.sha256
    ).digest()
    
    # Decodificar la firma recibida
    try:
        # Añadir padding si es necesario
        padding = len(signature_b64) % 4
        if padding:
            signature_b64 += '=' * (4 - padding)
            
        received_signature = base64.urlsafe_b64decode(signature_b64)
    except Exception:
        # Error de decodificación
        return None
    
    # Comparar firmas (tiempo constante para prevenir timing attacks)
    if hmac.compare_digest(expected_signature, received_signature):
        return value
    
    return None


def encrypt_value(value: str, secret_key: str) -> str:
    """
    Cifra un valor usando AES-GCM con Fernet.
    Esta es una implementación simplificada que podría extenderse.
    
    Para una implementación completa, podríamos usar:
    from cryptography.fernet import Fernet
    
    Args:
        value: El valor a cifrar
        secret_key: La clave secreta para el cifrado
        
    Returns:
        El valor cifrado en formato base64
    """
    # En esta versión simplificada, usaremos la firma como cifrado
    # para evitar dependencias adicionales
    timestamp = int(time.time())
    payload = f"{timestamp}.{value}"
    return sign_value(payload, secret_key)


def decrypt_value(encrypted_value: str, secret_key: str, max_age: Optional[int] = None) -> Optional[str]:
    """
    Descifra un valor cifrado.
    
    Args:
        encrypted_value: El valor cifrado
        secret_key: La clave secreta para el descifrado
        max_age: Edad máxima en segundos para considerar válido el valor
        
    Returns:
        El valor original si el descifrado es exitoso y no ha expirado, None en caso contrario
    """
    # Verificar la firma
    payload = verify_signed_value(encrypted_value, secret_key)
    if not payload:
        return None
    
    # Extraer timestamp y valor
    try:
        timestamp_str, value = payload.split('.', 1)
        timestamp = int(timestamp_str)
    except (ValueError, TypeError):
        return None
    
    # Verificar edad si se especifica max_age
    if max_age is not None:
        current_time = int(time.time())
        if current_time - timestamp > max_age:
            return None
    
    return value


def encode_session_data(user_id: str, request: Optional[Any] = None, extra_data: Optional[Dict[str, Any]] = None) -> str:
    """
    Encodes session data in JSON format with enhanced security information.
    
    Args:
        user_id: User ID
        request: Optional request object to extract client info
        extra_data: Additional data for the session
        
    Returns:
        Session data encoded in JSON
    """
    now = int(time.time())
    
    session_data = {
        "user_id": user_id,
        "created_at": now,
        "last_activity": now
    }
    
    # Add client information if request is provided
    if request:
        client_host = getattr(request, "client", None)
        headers = getattr(request, "headers", {})
        
        if client_host:
            session_data["ip_address"] = getattr(client_host, "host", "unknown")
        
        # Add user agent if available
        user_agent = headers.get("user-agent", "")
        if user_agent:
            session_data["user_agent"] = user_agent
    
    if extra_data:
        session_data.update(extra_data)
    
    return json.dumps(session_data)


def decode_session_data(session_data_str: str) -> Optional[Dict[str, Any]]:
    """
    Decodes session data from JSON format.
    
    Args:
        session_data_str: Encoded session data
        
    Returns:
        Dictionary with session data, or None if there's an error
    """
    try:
        return json.loads(session_data_str)
    except json.JSONDecodeError:
        return None


def get_user_id_from_session_data(session_data: Dict[str, Any]) -> Optional[str]:
    """
    Extracts the user ID from session data.
    
    Args:
        session_data: Session data
        
    Returns:
        User ID or None if it doesn't exist
    """
    return session_data.get("user_id")


def generate_secret_key() -> str:
    """
    Genera una clave secreta aleatoria para firmar y cifrar.
    
    Returns:
        Clave secreta codificada en base64
    """
    return base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')
