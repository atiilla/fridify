"""Messaging handler for Frida script communication."""

from frida_utils.common import logger

def on_message(message, data):
    """Handle messages from Frida scripts.
    
    Args:
        message: The message object from Frida
        data: Any binary data associated with the message
        
    This function handles both normal messages and error messages from Frida scripts.
    """
    if message["type"] == "send":
        logger.info(f"Message from Frida: {message['payload']}")
    elif message["type"] == "error":
        logger.error(f"Error from Frida: {message.get('stack', message)}") 