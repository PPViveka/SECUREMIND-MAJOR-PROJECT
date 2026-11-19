"""
SageArmor Intelligence Module
Code graph dependency analysis, cross-file attack paths, and threat modeling.
"""

from ..code_graph import (
    CodeGraph,
    build_code_graph,
    build_multi_file_code_graph,
    merge_with_heuristic_graph,
)
from ..attack_intelligence import (
    build_attack_intelligence,
    build_copilot_prompt,
)

__all__ = [
    "CodeGraph",
    "build_code_graph",
    "build_multi_file_code_graph",
    "merge_with_heuristic_graph",
    "build_attack_intelligence",
    "build_copilot_prompt",
]
