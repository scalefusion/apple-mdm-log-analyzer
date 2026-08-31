"""MDM/DDM Log Analyzer — local, stateless engine + MCP server."""

from importlib.metadata import PackageNotFoundError, version as _version

# Derived from installed metadata rather than hardcoded: a literal here drifted
# to 0.1.0 while pyproject said 1.0.0, so `mdm_log_analyzer.__version__` lied
# while the MCP handshake (which already read metadata) was correct.
try:
    __version__ = _version("mdm-log-analyzer")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "0+unknown"
