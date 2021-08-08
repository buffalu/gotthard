import logging
import logging.config
import os
import yaml


class HumanReadableContextFormatter(logging.Formatter):
    def formatMessage(self, record):
        formatted_str = self._style.format(record)
        formatted_str += " "
        if "context" in record.__dict__ and record.__dict__["context"]:
            str_to_add = ""
            for key, value in record.__dict__["context"].items():
                if isinstance(value, float):
                    str_to_add += f"{key}={value:2.2f} "
                else:
                    str_to_add += f"{key}={value} "
            formatted_str += str_to_add
        return formatted_str


class Logger(object):
    def __init__(self, cls):
        name = cls
        if not isinstance(cls, str):
            name = cls.__name__
        self._logger = logging.getLogger(name)
        self._logger.setLevel(logging.INFO)

    def d(self, msg, *args, **kwargs):
        self.log(logging.DEBUG, msg, *args, **kwargs)

    def i(self, msg, *args, **kwargs):
        self.log(logging.INFO, msg, *args, **kwargs)

    def w(self, msg, *args, **kwargs):
        self.log(logging.WARN, msg, *args, **kwargs)

    def e(self, msg, *args, **kwargs):
        self.log(logging.ERROR, msg, *args, **kwargs)

    def f(self, msg, *args, **kwargs):
        self.log(logging.FATAL, msg, *args, **kwargs)

    def log(self, level, msg, *args, **kwargs):
        extra = dict()
        extra["context"] = dict()
        del_keys = list()
        for key in kwargs.keys():
            if key not in ("exc_info"):
                extra["context"][key] = kwargs[key]
                del_keys.append(key)
        [kwargs.pop(key) for key in del_keys]

        self._logger.log(level, msg, *args, extra=extra, **kwargs)


def setup_logging(f_path):
    with open(f_path, 'rt') as f:
        config = yaml.safe_load(f.read())
        logging.config.dictConfig(config)
