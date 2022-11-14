import os
from Log.logger import logger
from asn1crypto import x509, pem


def cert_proc(cert_format, cert_name):
    if cert_format == 'der':
        if os.path.exists(cert_name):
            try:
                with open(cert_name, "rb") as f:
                    cert_bytes = f.read()
            except Exception as e:
                logger.warning(f"Open file: {cert_name} occurred exception: {e}")
            try:
                return x509.Certificate.load(cert_bytes)
            except ValueError as e:
                logger.warning(f"Analyze asn1 struct occurred exception: {e}")
        else:
            logger.warning(f"Can't found file: {cert_name}")

    elif cert_format == 'pem':
        pass

    elif cert_format == 'base64':
        pass

    else:
        print(f"unknown input format {cert_format}")

