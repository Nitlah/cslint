from Log.logger import logger
from asn1crypto.x509 import Certificate


def str_to_list(tmp_str):
    try:
        tmp_list = []
        for tmp_lint in tmp_str.split(','):
            tmp_list.append(tmp_lint.replace(' ', ''))
        return tmp_list
    except Exception as e:
        logger.warning(f"Analyze str list failed, an error occurred: {e}")


def handle_errors(error_list):
    """Record errors in error_list."""
    if not error_list:
        return
    for name, err in error_list:
        logger.warning(f"Lint: {name} import failed: {err}")


def get_extensions(cert, extn_id):
    """
    '2.5.29.9': 'subject_directory_attributes',
    '2.5.29.14': 'key_identifier',
    '2.5.29.15': 'key_usage',
    '2.5.29.16': 'private_key_usage_period',
    '2.5.29.17': 'subject_alt_name',
    '2.5.29.18': 'issuer_alt_name',
    '2.5.29.19': 'basic_constraints',
    '2.5.29.30': 'name_constraints',
    '2.5.29.31': 'crl_distribution_points',
    '2.5.29.32': 'certificate_policies',
    '2.5.29.33': 'policy_mappings',
    '2.5.29.35': 'authority_key_identifier',
    '2.5.29.36': 'policy_constraints',
    '2.5.29.37': 'extended_key_usage',
    '2.5.29.46': 'freshest_crl',
    '2.5.29.54': 'inhibit_any_policy',
    '1.3.6.1.5.5.7.1.1': 'authority_information_access',
    '1.3.6.1.5.5.7.1.11': 'subject_information_access',
    '1.3.6.1.5.5.7.1.24': 'tls_feature',
    '1.3.6.1.5.5.7.48.1.5': 'ocsp_no_check',
    '1.2.840.113533.7.65.0': 'entrust_version_extension',
    '2.16.840.1.113730.1.1': 'netscape_certificate_type',
    '1.3.6.1.4.1.11129.2.4.2': 'signed_certificate_timestamp_list',
    '1.3.6.1.4.1.311.20.2': 'microsoft_enroll_certtype',
    """
    if not isinstance(cert, Certificate):
        logger.warning("Cert type error")
        return None
    extensions = cert['tbs_certificate']['extensions']
    if extensions:
        for ext in extensions:
            if ext['extn_id'].native == extn_id or ext['extn_id'].dotted == extn_id:
                return ext


if __name__ == '__main__':
    with open("/Users/infosec/Documents/PythonProject/zlint/1231012a66594983d83ab1b32e2e1233", "rb") as f:
        e = get_extensions(Certificate.load(f.read()), '2.5.29.19')
        print(e.native)
