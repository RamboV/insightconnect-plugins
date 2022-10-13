# GENERATED BY KOMAND SDK - DO NOT EDIT
from setuptools import setup, find_packages


setup(name="microsoft_teams-rapid7-plugin",
      version="4.0.1",
      description="The Microsoft Teams plugin allows you to send and trigger workflows on new messages. The plugin will also allow for teams management with the ability to add and remove teams, channels, and users",
      author="rapid7",
      author_email="",
      url="",
      packages=find_packages(),
      install_requires=['insightconnect-plugin-runtime'],  # Add third-party dependencies to requirements.txt, not here!
      scripts=['bin/icon_microsoft_teams']
      )
