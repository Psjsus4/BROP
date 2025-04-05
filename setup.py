from setuptools import setup
import os
import sys
from distutils.sysconfig import get_python_inc

# Check if Python.h is present
python_header = os.path.join(get_python_inc(), 'Python.h')
if not os.path.exists(python_header):
    print("You must install the Python development headers!", file=sys.stderr)
    print("$ sudo apt-get install python3-dev", file=sys.stderr)  # Use python3-dev for Python 3
    sys.exit(-1)

setup(
    name="brop",
    version="1.0.0",
    entry_points={
        "console_scripts": [
            "bropper = broplib.cli.bropper:main"
        ]
    }
)