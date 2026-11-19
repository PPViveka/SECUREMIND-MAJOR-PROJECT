"""
Benchmark Test Cases: Eval Injection & Insecure Deserialization - Guarded Patterns (10 cases)
Ground Truth: GUARDED / BENIGN (False Positive Controls)
"""

import ast
import json
import yaml


def calculate_expression_safe(expr_str):
    """Guarded: ast.literal_eval prevents code execution (dev)"""
    return ast.literal_eval(expr_str)


def execute_action_safe(action_name):
    """Guarded: Explicit function lookup dictionary replaces exec (dev)"""
    handlers = {
        "status": lambda: "ok",
        "ping": lambda: "pong",
        "count": lambda: 10,
    }
    if action_name not in handlers:
        raise ValueError("Invalid action")
    return handlers[action_name]()


def deserialize_session_safe(token_data):
    """Guarded: JSON parsing replaces pickle deserialization (dev)"""
    return json.loads(token_data)


def parse_user_yaml_safe(yaml_str):
    """Guarded: yaml.safe_load blocks arbitrary Python objects (dev)"""
    return yaml.safe_load(yaml_str)


def dynamic_filter_safe(record, filter_prop):
    """Guarded: getattr allowlist prevents code execution (dev)"""
    allowed_props = {"id", "name", "status", "created_at"}
    if filter_prop not in allowed_props:
        raise ValueError("Invalid property")
    return getattr(record, filter_prop, None)


def evaluate_formula_safe(formula):
    """Guarded: ast.literal_eval for safe literal evaluation (eval)"""
    return ast.literal_eval(formula)


def run_user_script_safe(script_key):
    """Guarded: Whitelisted routine lookup replaces exec (eval)"""
    registry = {"hello": "Hello World", "version": "1.0.0"}
    if script_key not in registry:
        raise KeyError("Script not recognized")
    return registry[script_key]


def load_cached_object_safe(raw_text):
    """Guarded: json.loads replaces pickle (eval)"""
    return json.loads(raw_text)


def parse_config_payload_safe(payload):
    """Guarded: yaml.safe_load replaces unsafe_load (eval)"""
    return yaml.safe_load(payload)


def compute_metric_safe(metric_name, x, y):
    """Guarded: Operator lookup dictionary replaces dynamic eval (eval)"""
    ops = {
        "+": lambda a, b: a + b,
        "-": lambda a, b: a - b,
        "*": lambda a, b: a * b,
    }
    if metric_name not in ops:
        raise ValueError("Unsupported operator")
    return ops[metric_name](float(x), float(y))
