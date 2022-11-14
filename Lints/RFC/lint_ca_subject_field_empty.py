from Base.base import Registers, LintBase
from asn1crypto.x509 import Certificate


@Registers.lint.register('rfc_ext_ca_subject_field_empty')
class Constraints(LintBase):

    def __init__(self):
        self.name = "rfc_ext_ca_subject_field_empty"
        self.description = "CA Certificates subject field \
        MUST not be empty and MUST have a non-empty distinguished name"
        self.citation = "RFC 5280: 4.1.2.6"
        self.source = "RFC 5280"
        self.effective_date = "1999-01-01"

    def execute(self, cert):
        if not isinstance(cert, Certificate):
            return "UNKNOWN"
        elif len(cert.subject.native) >= 1:
            return "PASS"
        else:
            return "ERROR"

    def check_applies(self, cert):
        if isinstance(cert, Certificate):
            return cert.ca
        else:
            return True
