# GENERATED BY KOMAND SDK - DO NOT EDIT
from setuptools import setup, find_packages


setup(name="trufflehog-rapid7-plugin",
      version="1.1.3",
      description="Search through git repositories for high entropy strings and secrets, digging deep into commit history",
      author="rapid7",
      author_email="",
      url="",
      packages=find_packages(),
      install_requires=['komand'],  # Add third-party dependencies to requirements.txt, not here!
      scripts=['bin/komand_trufflehog']
      )
