# Copyright (c) 2026 Maksym Bardakh. All rights reserved.
# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Source-available under LICENSE.md with the permissions in LICENSING.md.

import os
from pathlib import Path

Import("env")

idf_path = Path(env.PioPlatform().get_package_dir("framework-espidf"))
os.environ["GIT_CEILING_DIRECTORIES"] = str(idf_path.parent.parent)