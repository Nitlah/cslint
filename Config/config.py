import os

# module
MAIN_LINT_PATH = 'Lints'
LINT_TYPE = [
    'RFC',
    'CSBR',
    'Others'
]

# log path
LOG_PATH = os.path.abspath(os.path.dirname(os.getcwd())) + '/Log/error.log'

# lint result
LINT_RESULT = ['RS', 'NA', 'NE', 'PASS', 'NOTICE', 'WARN', 'ERROR', 'FATAL', 'UNKNOWN']
