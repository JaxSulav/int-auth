import base64


def encodb64(client_id, client_secret):
    key = client_id + ':' + client_secret
    message_bytes = key.encode("utf-8")
    base64_bytes = base64.b64encode(message_bytes)
    return base64_bytes
