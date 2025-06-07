"""Common utilities and logging configuration for the Frida utilities package."""

import subprocess
import frida
import logging
import os
import time
import platform
import requests
import zipfile
import io
import re
import json
import lzma

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("frida_utils") 