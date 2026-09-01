from __future__ import annotations

from typing import Any

# https://kubernetes.io/docs/concepts/windows/user-guide/
# https://kubernetes.io/docs/reference/labels-annotations-taints/#beta-kubernetes-io-os-deprecated
WINDOWS_OS_LABEL_KEYS = ("kubernetes.io/os", "beta.kubernetes.io/os")
WINDOWS_OS_VALUE = "windows"


def extract_commands(conf: dict[str, Any]) -> tuple[list[str], list[str]]:
    commands = conf.get("command")
    if not commands or not isinstance(commands, list):
        return [], []
    values = []
    keys = []
    for cmd in commands:
        if cmd is None:
            continue
        if "=" in cmd:
            key, value = cmd.split("=", maxsplit=1)
            keys.append(key)
            values.append(value)
        else:
            keys.append(cmd)
            values.append(None)
    return keys, values


def is_windows_pod_spec(spec: Any) -> bool:
    """Return True when the pod spec strongly and exclusively targets Windows."""
    if not isinstance(spec, dict):
        return False
    if _has_windows_os_name(spec):
        return True
    if _has_windows_node_selector(spec):
        return True
    if _has_windows_required_node_affinity(spec):
        return True
    return False


def _has_windows_os_name(spec: dict[str, Any]) -> bool:
    os_field = spec.get("os")
    if not isinstance(os_field, dict):
        return False
    return _is_windows_value(os_field.get("name"))


def _has_windows_node_selector(spec: dict[str, Any]) -> bool:
    node_selector = spec.get("nodeSelector")
    if not isinstance(node_selector, dict):
        return False
    for label_key in WINDOWS_OS_LABEL_KEYS:
        if _is_windows_value(node_selector.get(label_key)):
            return True
    return False


def _has_windows_required_node_affinity(spec: dict[str, Any]) -> bool:
    affinity = spec.get("affinity")
    if not isinstance(affinity, dict):
        return False
    node_affinity = affinity.get("nodeAffinity")
    if not isinstance(node_affinity, dict):
        return False

    required = node_affinity.get("requiredDuringSchedulingIgnoredDuringExecution")
    if not isinstance(required, dict):
        return False

    node_selector_terms = required.get("nodeSelectorTerms")
    if not isinstance(node_selector_terms, list) or not node_selector_terms:
        return False

    return all(_term_requires_windows(term) for term in node_selector_terms)


def _term_requires_windows(term: Any) -> bool:
    if not isinstance(term, dict):
        return False

    for matcher_key in ("matchExpressions", "matchFields"):
        matchers = term.get(matcher_key)
        if not isinstance(matchers, list):
            continue
        for expression in matchers:
            if _match_requires_windows(expression):
                return True
    return False


def _match_requires_windows(expression: Any) -> bool:
    if not isinstance(expression, dict):
        return False
    if expression.get("key") not in WINDOWS_OS_LABEL_KEYS:
        return False

    operator = expression.get("operator")
    if not isinstance(operator, str) or operator.lower() != "in":
        return False

    values = expression.get("values")
    if not isinstance(values, list) or not values:
        return False

    return all(_is_windows_value(value) for value in values)


def _is_windows_value(value: Any) -> bool:
    if isinstance(value, list):
        return any(_is_windows_value(item) for item in value)
    return isinstance(value, str) and value.lower() == WINDOWS_OS_VALUE
