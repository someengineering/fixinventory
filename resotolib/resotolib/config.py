from typing import ClassVar, Dict, Any


class Config:
    """
    This class is used to store all the configuration variables.
    """

    __config: ClassVar[Dict[str, Any]] = {}

    def __init__(self, name: str):
        self.name = name

    def __getitem__(self, key):
        print("__getitem__")
        return self.__config[key]

    def __setitem__(self, key, value):
        print("__setitem__")
        self.__config[key] = value

    def __delitem__(self, key):
        print("__delitem__")
        del self.__config[key]

    def __iter__(self):
        print("__iter__")
        return iter(self.__config)

    def __len__(self):
        print("__len__")
        return len(self.__config)

    def __contains__(self, key):
        print("__contains__")
        return key in self.__config

    def __str__(self):
        print("__str__")
        return str(self.__config)

    def __repr__(self):
        print("__repr__")
        return repr(self.__config)

    def __getattr__(self, name):
        print("__getattr__")
        if name not in self.__config:
            self.__config[name] = {}
        return self.__config[name]

    def __setattr__(self, name, value):
        print("__setattr__")
        self.__config[name] = value

    def __delattr__(self, name):
        print("__delattr__")
        del self.__config[name]

    def __getstate__(self):
        print("__getstate__")
        return self.__config

    def __setstate__(self, state):
        print("__setstate__")
        self.__config = state

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        pass
