"""
config/loader.py
YAML attack profile loader.

Profiles allow defining and saving attack configs:
  floodles profile run ./config/examples/http_stress.yaml

Example profile:
  module: http_flood
  target: http://192.168.1.100/search
  params:
    method: GET
    concurrency: 1000
    duration: 60
    cache_bust: true
"""

import os
from pathlib import Path
from typing import Any

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


SUPPORTED_MODULES = {
    "syn_flood", "udp_flood", "icmp_flood",
    "http_flood", "slowloris", "ntp_amp",
    "xmas_flood", "ack_flood", "dns_amp",
}


class ConfigError(Exception):
    pass


def load(path: str) -> dict:
    """
    Load and validate a YAML attack profile.

    Returns dict with keys:
      module  : str
      target  : str (IP or URL)
      params  : dict of module-specific kwargs
      meta    : dict (optional: name, description, author)
    """
    if not YAML_AVAILABLE:
        raise ImportError("PyYAML required: pip install pyyaml")

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Profile not found: {path}")

    with open(p) as f:
        data = yaml.safe_load(f)

    _validate(data, path)
    return data


def _validate(data: dict, path: str) -> None:
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: root must be a YAML mapping")

    for key in ("module", "target"):
        if key not in data:
            raise ConfigError(f"{path}: missing required field '{key}'")

    module = data["module"]
    if module not in SUPPORTED_MODULES:
        raise ConfigError(
            f"{path}: unknown module '{module}'. "
            f"Supported: {', '.join(sorted(SUPPORTED_MODULES))}"
        )

    if "params" not in data:
        data["params"] = {}

    if not isinstance(data["params"], dict):
        raise ConfigError(f"{path}: 'params' must be a mapping")


def generate_example(module: str, output_path: str) -> None:
    """Write an example profile for the given module."""
    templates = {
        "syn_flood": {
            "module": "syn_flood",
            "target": "192.168.1.100",
            "meta": {"name": "SYN flood example", "author": ""},
            "params": {
                "port": 80,
                "threads": 32,
                "pps_limit": 0,
                "duration": 60,
                "spoof": True,
            },
        },
        "http_flood": {
            "module": "http_flood",
            "target": "http://192.168.1.100/",
            "meta": {"name": "HTTP GET flood", "author": ""},
            "params": {
                "method": "GET",
                "concurrency": 1000,
                "duration": 60,
                "cache_bust": True,
                "post_size": 1024,
            },
        },
        "slowloris": {
            "module": "slowloris",
            "target": "192.168.1.100",
            "meta": {"name": "Slowloris exhaustion", "author": ""},
            "params": {
                "port": 80,
                "socket_count": 300,
                "keep_alive_interval": 10.0,
                "duration": 120,
                "use_ssl": False,
            },
        },
        "udp_flood": {
            "module": "udp_flood",
            "target": "192.168.1.100",
            "meta": {"name": "UDP volumetric", "author": ""},
            "params": {
                "port": 0,
                "payload_size": 1400,
                "threads": 16,
                "duration": 60,
                "spoof": True,
            },
        },
        "ntp_amp": {
            "module": "ntp_amp",
            "target": "192.168.1.100",
            "meta": {"name": "NTP amplification", "author": ""},
            "params": {
                "reflectors": ["1.2.3.4", "5.6.7.8"],
                "threads": 8,
                "duration": 30,
            },
        },
    }

    if module not in templates:
        raise ConfigError(f"No template for module '{module}'")

    if not YAML_AVAILABLE:
        raise ImportError("PyYAML required: pip install pyyaml")

    with open(output_path, "w") as f:
        yaml.dump(templates[module], f, default_flow_style=False, sort_keys=False)
