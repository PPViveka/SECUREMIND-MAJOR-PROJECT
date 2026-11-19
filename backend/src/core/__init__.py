"""
SageArmor Core Module
Core data models, configuration, job management, and function caching.
"""

from ..config import config, AppConfig, SecurityConfig, ServerConfig, StorageConfig, AIConfig
from ..finding_schema import (
    SCHEMA_VERSION,
    normalize_finding,
    normalize_findings,
    validate_finding,
    anchor_findings,
)
from ..job_manager import (
    create_job,
    get_job,
    set_db_path,
    add_job_event,
    record_stage_timing,
    update_job_progress,
)
from ..function_cache import (
    FunctionScanCache,
    SelectiveFunctionScanner,
    extract_functions,
    extract_python_functions,
    extract_generic_functions,
    compute_function_hash,
    RISKY_SINKS,
)

__all__ = [
    "config",
    "AppConfig",
    "SecurityConfig",
    "ServerConfig",
    "StorageConfig",
    "AIConfig",
    "SCHEMA_VERSION",
    "normalize_finding",
    "normalize_findings",
    "validate_finding",
    "anchor_findings",
    "create_job",
    "get_job",
    "set_db_path",
    "add_job_event",
    "record_stage_timing",
    "update_job_progress",
    "FunctionScanCache",
    "SelectiveFunctionScanner",
    "extract_functions",
    "extract_python_functions",
    "extract_generic_functions",
    "compute_function_hash",
    "RISKY_SINKS",
]
