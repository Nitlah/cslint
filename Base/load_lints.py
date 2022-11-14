import os
import importlib
from Config.config import *
from Utils.utils import handle_errors


def get_lint_name(type_path):
    """Get lint name in each source"""
    dir_path = os.path.dirname(__file__)
    file_obj = os.walk(dir_path + '/../' + type_path)
    for _, _, file_list in file_obj:
        for lint_file in file_list:
            if '__init__' not in lint_file:
                yield lint_file[:-3]


def import_all_lints_for_register(custom_lints=None, exclude_sources=None):
    """Import all lints for register."""
    errors = []
    lints = []

    for lint_type in LINT_TYPE:
        if exclude_sources and lint_type in exclude_sources:
            continue
        lint_type_path = MAIN_LINT_PATH + '/' + lint_type
        for lint_file in get_lint_name(lint_type_path):
            lint_path = MAIN_LINT_PATH + '.' + lint_type + '.' + lint_file
            lints.append(lint_path)

    if isinstance(custom_lints, list):
        lints += custom_lints

    for lint_file in lints:
        try:
            importlib.import_module(lint_file)
        except ImportError as error:
            errors.append((lint_file, error))

    handle_errors(errors)


def exclude_lints(registers, name_list=None):
    if name_list:
        for lint_name in name_list:
            registers.lint.lint_dict.pop(lint_name)
