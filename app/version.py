"""ThreatRadar Version and Metadata
Centralized Semantic Versioning (SemVer)
"""

__version__ = "1.5.4"
__app_name__ = "ThreatRadar"
__description__ = "Autonomous Standalone Cyber Threat Intelligence Hub & SOC Radar"
__release_date__ = "2026-09-28"
__author__ = "ThreatRadar Team"
__license__ = "MIT"


def get_version_info() -> dict:
    """Return dictionary of centralized version metadata."""
    return {
        "version": __version__,
        "app_name": __app_name__,
        "description": __description__,
        "release_date": __release_date__,
        "author": __author__,
        "license": __license__,
    }
