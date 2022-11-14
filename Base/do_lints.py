from Base.base import LintBase
from Log.logger import logger
from asn1crypto.x509 import Certificate
from Config.config import LINT_RESULT


def do_lints(registers, cert):

    cache_dict = {}
    if not isinstance(cert, Certificate):
        logger.warning("Cert not well formed")
        return

    # lint check
    for k, v in registers.lint.lint_dict.items():
        lint_obj = v()
        if not isinstance(lint_obj, LintBase):
            logger.warning(f"Lint name: {k} is not LintBase type ")
            continue
        if lint_obj.check_applies(cert):
            cache_dict[k] = lint_obj.execute(cert)
        else:
            cache_dict[k] = 'NA'

    # check result format
    for lint_name, check_result in cache_dict.items():
        if check_result not in LINT_RESULT:
            cache_dict[lint_name] = 'UNKNOWN'

    print(cache_dict)
