"""This module contains basic (naive) package name identifier."""


from cvejob.config import Config


class KnownPackageNameIdentifier(object):
    """Package name is already known, no need to guess."""

    def __init__(self, doc):
        """Constructor."""
        self._doc = doc

    def identify(self):
        return [{'package': Config.package_name, 'score': '10.0'}]
