"""analyzer.py — 薄层兼容层，所有实现已拆分到 analysis/ 包。"""

import warnings
from intelpwn.core.analysis import *  # noqa: F401, F403

warnings.warn(
    "直接 import intelpwn.core.analyzer 已弃用; 请用 intelpwn.core.analysis",
    DeprecationWarning,
    stacklevel=2,
)
