from setuptools import setup

setup(
    name="floodles",
    version="2.0.0",
    description="Modular DoS/DDoS testing toolkit",
    package_dir={"floodles": "."},
    packages=[
        "floodles",
        "floodles.cli",
        "floodles.core",
        "floodles.modules",
        "floodles.config",
        "floodles.utils",
    ],
    python_requires=">=3.10",
    install_requires=[
        "scapy>=2.5.0",
        "aiohttp>=3.9.0",
        "click>=8.1.0",
        "rich>=13.7.0",
        "pyyaml>=6.0",
    ],
    entry_points={
        "console_scripts": [
            "floodles=floodles.cli.main:cli",
        ],
    },
)
