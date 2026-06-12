"""Token-efficient MCP server for Palo Alto Networks PAN-OS firewalls and Panorama.

Designed around three principles:
  1. Lean responses by default — typical 40-70% token reduction vs unfiltered output.
  2. Default-deny RBAC — only read tools are exposed unless PANOS_MODE opts in.
  3. TLS verification on by default — self-signed certs require explicit opt-in.

See the README for installation, configuration, and the full tool catalog.
"""

# pan-os-python 1.12.x still imports `distutils`, which Python 3.12 removed.
# We alias setuptools._distutils into sys.modules BEFORE any pan-os-python
# import so the legacy import still works. This shim is intentionally near
# the top of the package init to run before any submodule import.
#
# Track upstream resolution at:
#   https://github.com/PaloAltoNetworks/pan-os-python/issues
# When pan-os-python ships a 1.13+ that drops distutils, this shim can go.
import sys as _sys

if "distutils" not in _sys.modules:
    try:
        from setuptools import _distutils as _legacy_distutils
        from setuptools._distutils import version as _legacy_version

        _sys.modules["distutils"] = _legacy_distutils
        _sys.modules["distutils.version"] = _legacy_version
    except ImportError:
        # setuptools missing or doesn't expose _distutils; pan-os-python will
        # fail to import with a clear error and the operator can install
        # setuptools manually.
        pass

__version__ = "0.1.6"
