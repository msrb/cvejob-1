"""This module contains default package name selector."""

import logging
from cpe import CPE
from collections import defaultdict

from cvejob.config import Config
from cvejob.version import BenevolentVersion
from cvejob.utils import (
    get_java_versions,
    get_javascript_versions,
    get_python_versions
)


logger = logging.getLogger(__name__)


class VersionExistsSelector(object):
    """Selectors which picks winners based on existence of versions mentioned in the CVE record."""

    def __init__(self, cve, candidates):
        """Constructor."""
        self._cve = cve
        self._candidates = candidates

    def pick_winner(self):
        """Pick single winner.

        Or no winner, if all candidates fail the version check.
        """
        cpe_dicts = self._cve.get_cpe(cpe_type='a', nodes=self._cve.configurations)
        vpv_pairs = self._get_vpv_pairs(cpe_dicts)
        self._add_affected_versions(vpv_pairs)

        for vendor_product, versions in vpv_pairs.items():
            if versions:
                for candidate in self._candidates:
                    package = candidate['package']

                    versions_set = {BenevolentVersion(x) for x in versions}
                    upstream_versions_set = {
                        BenevolentVersion(x) for x in self._get_upstream_versions(package)
                    }
                    logger.info(
                        '{cve_id} Version-checking {vp}/{p}: cve({cv}), u({uv})'.format(
                            cve_id=self._cve.cve_id, vp=vendor_product, p=package,
                            cv=versions_set, uv=upstream_versions_set
                        )
                    )

                    # check if all versions mentioned in the CVE exist
                    # for given package name; if not, this is a false positive
                    result_set = versions_set - upstream_versions_set
                    logger.info(
                        '{cve_id} Version-checking result: {r}'.format(
                            cve_id=self._cve.cve_id, r=result_set
                        )
                    )
                    if result_set:
                        logger.info(
                            '{cve_id} Hit for package name: {package}'.format(
                                cve_id=self._cve.cve_id, package=package
                            )
                        )
                        return candidate

    def _get_upstream_versions(self, package):
        if Config.ecosystem == 'java':
            return get_java_versions(package)
        elif Config.ecosystem == 'python':
            return get_python_versions(package)
        elif Config.ecosystem == 'javascript':
            return get_javascript_versions(package)
        else:
            raise ValueError('Unsupported ecosystem {e}'.format(e=Config.ecosystem))

    def _get_vpv_pairs(self, cpe_dicts):
        # (vendor, product) -> set(versions) pairs
        vpv_pairs = defaultdict(lambda: set())

        for cpe in cpe_dicts:
            if cpe.versionStartIncluding is not None:
                vpv_pairs[(cpe.vendor(), cpe.product())].add(cpe.versionStartIncluding)
            if cpe.versionStartExcluding is not None:
                vpv_pairs[(cpe.vendor(), cpe.product())].add(cpe.versionStartExcluding)
            if cpe.versionEndIncluding is not None:
                vpv_pairs[(cpe.vendor(), cpe.product())].add(cpe.versionEndIncluding)
            if cpe.versionEndExcluding is not None:
                vpv_pairs[(cpe.vendor(), cpe.product())].add(cpe.versionEndExcluding)

            uri_version = CPE(cpe.cpe22Uri).get_version()
            if uri_version:
                vpv_pairs[(cpe.vendor, cpe.product)].add(uri_version[0])

        return vpv_pairs

    def _add_affected_versions(self, vpv_pairs):
        for vendor_product, versions in vpv_pairs.items():
            versions |= set(self._cve.get_affected_versions(vendor_product))
