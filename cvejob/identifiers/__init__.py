"""This package contains identifiers.

Identifiers are responsible for identifying package name candidates.
"""

from cvejob.config import Config
from cvejob.identifiers.basic import NaivePackageNameIdentifier
from cvejob.identifiers.namehint import KnownPackageNameIdentifier


def get_identifier(cve):
    """Get identifier object."""
    if Config.package_name:
        cls = KnownPackageNameIdentifier
    elif not Config.use_nvdtoolkit:
        cls = NaivePackageNameIdentifier
    else:
        raise NotImplementedError(
            "Identifier 'nvd-toolkit' is currently disabled due to nvdlib version incompatibility."
            " See nvd-toolkit migration status at:"
            " https://github.com/fabric8-analytics/fabric8-analytics-nvd-toolkit"
        )
        # cls = NvdToolkitPackageNameIdentifier
    return cls(cve)
