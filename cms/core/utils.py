import botocore

def safe_call(func, *args, **kwargs):
    """
    Ejecuta una llamada a la API y devuelve None si hay error de permisos o recurso inexistente.
    """
    try:
        return func(*args, **kwargs)
    except botocore.exceptions.ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("AccessDenied", "NoSuchBucket", "NoSuchPublicAccessBlockConfiguration"):
            return None
        raise

def paginate(client_method, result_key, **kwargs):
    """
    Itera sobre todas las páginas de un método de cliente boto3.
    """
    paginator = client_method.__self__.get_paginator(client_method.__name__)
    for page in paginator.paginate(**kwargs):
        for item in page.get(result_key, []):
            yield item
