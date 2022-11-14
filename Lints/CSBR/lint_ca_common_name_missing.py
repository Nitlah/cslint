from Base.base import Registers, LintBase
from Utils.utils import get_extensions
from asn1crypto.x509 import Certificate


@Registers.lint.register('csbr_ext_ca_common_name_missing')
class CACommonName(LintBase):

    def __init__(self):
        self.name = "csbr_ext_ca_common_name_missing"
        self.description = "CA Certificates common name MUST be included."
        self.citation = "BRs: 7.1.4.3.1"
        self.source = "BRs"
        self.effective_date = "2017-06-08"

    def execute(self, cert):
        if isinstance(cert, Certificate):
            try:
                if cert.subject.native['common_name']:
                    return "PASS"
            except KeyError:
                return "ERROR"
        else:
            return "UNKNOWN"

    def check_applies(self, cert):
        if isinstance(cert, Certificate):
            return cert.ca
        else:
            return True
