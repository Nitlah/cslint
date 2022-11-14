from Base.base import Registers, LintBase
from Utils.utils import get_extensions
from asn1crypto.x509 import Certificate


@Registers.lint.register('rfc_ext_basic_constraint_not_critical')
class Constraints(LintBase):

    def __init__(self):
        self.name = "rfc_ext_basic_constraint_not_critical"
        self.description = "basicConstraints MUST appear as a critical extension"
        self.citation = "RFC 5280: 4.2.1.9"
        self.source = "RFC 5280"
        self.effective_date = "1999-01-01"

    def execute(self, cert):
        ext = get_extensions(cert, 'basic_constraints')
        if ext:
            if ext['critical']:
                return "PASS"
            else:
                return "ERROR"
        else:
            return "NA"

    def check_applies(self, cert):
        if isinstance(cert, Certificate):
            return cert.ca and get_extensions(cert, 'basic_constraints')
        else:
            return True
