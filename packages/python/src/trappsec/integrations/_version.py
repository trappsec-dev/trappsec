"""Warn when a framework is older than the oldest version trappsec is tested on."""
import importlib.metadata
import re


def warn_if_older(logger, distribution, minimum, consequence):
    """Log an error if ``distribution`` is installed below ``minimum`` (a tuple). Never raises."""
    try:
        version = importlib.metadata.version(distribution)
        parts = tuple(int(x) for x in re.findall(r"\d+", version)[:len(minimum)])
    except Exception:
        return
    if parts and parts < tuple(minimum):  # an unparseable version is not evidence of an old one
        logger.error(
            "trappsec: %s %s is older than the oldest supported version %s; %s",
            distribution, version, ".".join(str(x) for x in minimum), consequence)
