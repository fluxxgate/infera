from setuptools import setup, find_packages

setup(
    name="inferas",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "requests",
        "beautifulsoup4",
        "aiohttp"
    ],
    author="fluxxgate",
    description="web + reverse engineering toolkit",
    url="https://github.com/fluxxgate/inferas",
)
