from abc import ABCMeta, abstractmethod
from Log.logger import logger


class LintBase(metaclass=ABCMeta):

    @abstractmethod
    def execute(self, x509_cert):
        """
        -- Reserved --
        RS
        -- Not Applicable --
        NA
        -- Not Effective --
        NE
        -- Normal --
        Pass, Notice, Warn, Error, Fatal
        -- Exception --
        UNKNOWN
        """
        pass

    @abstractmethod
    def check_applies(self, x509_cert):
        pass


class Register:

    def __init__(self, registry_name=None):
        self.lint_dict = {}
        self.lint_name = registry_name

    def register(self, target):
        """Decorator to register a function or class."""

        def add(key, value):
            self[key] = value
            return value

        if callable(target):
            return add(None, target)
        return lambda x: add(target, x)

    def __setitem__(self, key, value):
        if not callable(value):
            raise Exception(f"Value of a Registry must be a callable!\nValue: {value}")
        if key is None:
            key = value.__name__
        if key in self.lint_dict:
            logger.warning(f"Lint name: {key} already in registry {self.lint_name}")
        self.lint_dict[key] = value

    def __getitem__(self, key):
        return self.lint_dict[key]

    def __contains__(self, key):
        return key in self.lint_dict


class Registers:

    def __init__(self):
        raise RuntimeError("Registries is not intended to be instantiated")

    lint = Register()
