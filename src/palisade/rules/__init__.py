"""Rule package.

Importing this module is what populates the registry: each rule module applies
the :func:`palisade.rules.base.register` decorator at import time, so adding a
detection means dropping a module here and listing it below.
"""

from palisade.rules import concealment, exfiltration, injection, schema_risk, shadowing
from palisade.rules.base import Rule, all_rules, register
from palisade.rules.shadowing import CrossServerRule

__all__ = [
    "Rule",
    "CrossServerRule",
    "all_rules",
    "register",
    "concealment",
    "exfiltration",
    "injection",
    "schema_risk",
    "shadowing",
]
