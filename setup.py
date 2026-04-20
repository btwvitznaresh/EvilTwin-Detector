from setuptools import setup, find_packages

setup(
    name="eviltwin_detector",
    version="0.1.0",
    description="A Python tool to detect evil twin Wi-Fi access points",
    author="Your Name",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "scapy",
        "pywifi",
        "rich",
        "streamlit",
        "plotly",
        "fastapi",
        "pandas",
        "pyyaml",
        "requests",
    ],
    extras_require={
        "dev": ["pytest"],
    },
)
