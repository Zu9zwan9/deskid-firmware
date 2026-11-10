import os
from pathlib import Path

Import("env")

idf_path = Path(env.PioPlatform().get_package_dir("framework-espidf"))
os.environ["GIT_CEILING_DIRECTORIES"] = str(idf_path.parent.parent)