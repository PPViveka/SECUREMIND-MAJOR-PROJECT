"""
Benchmark Test Cases: Eval Injection & Insecure Deserialization - Vulnerable Patterns (10 cases)
Ground Truth: VULNERABLE
"""

import pickle
import yaml


def calculate_expression(expr_str):
    """Vulnerable: Direct eval of untrusted mathematical expression (dev)"""
    return eval(expr_str)


def execute_action(action_code):
    """Vulnerable: exec on arbitrary user-provided code (dev)"""
    exec(action_code)
    return True


def deserialize_session(token_data):
    """Vulnerable: pickle.loads on untrusted serialized payload (dev)"""
    return pickle.loads(token_data)


def parse_user_yaml(yaml_str):
    """Vulnerable: unsafe yaml.load allows arbitrary object instantiation (dev)"""
    return yaml.load(yaml_str, Loader=yaml.Loader)


def dynamic_filter(record, filter_code):
    """Vulnerable: eval used for dynamic record filtering (dev)"""
    return eval(f"record.{filter_code}")


def evaluate_formula(formula, context):
    """Vulnerable: eval with unconstrained globals and user formula (eval)"""
    return eval(formula, context)


def run_user_script(script_text):
    """Vulnerable: exec executing user-submitted script (eval)"""
    locs = {}
    exec(script_text, {}, locs)
    return locs


def load_cached_object(raw_bytes):
    """Vulnerable: pickle.loads on unauthenticated cached bytes (eval)"""
    return pickle.loads(raw_bytes)


def parse_config_payload(payload):
    """Vulnerable: yaml.unsafe_load on incoming user config (eval)"""
    return yaml.unsafe_load(payload)


def compute_metric(metric_name, x, y):
    """Vulnerable: eval string concatenation for metric calculation (eval)"""
    return eval(f"{x} {metric_name} {y}")
