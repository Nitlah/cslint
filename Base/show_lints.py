import re


def show_lints_json(registers):
    for k, v in registers.lint.lint_dict.items():
        print(k, v)


def show_lints_source(registers):
    lint_source_set = set()
    for k, v in registers.lint.lint_dict.items():
        source = re.findall(r"Lints\.([^.]*)\.", str(v))
        lint_source_set.add(source[0])
    for source in lint_source_set:
        print(source)
