"""Access control policies for VaultLite.

Policies define what operations a token can perform on which paths.
Each policy contains rules mapping path patterns to capabilities.

Path matching supports glob-style wildcards:
- "secret/data/*" matches "secret/data/db" but not "secret/data/db/pass"
- "secret/data/**" matches everything under "secret/data/"
- Exact paths match exactly

Default-deny: if no policy grants a capability, the operation is denied.
"""

from __future__ import annotations

import fnmatch
from typing import Optional

from vaultlite.types import Policy, Rule
from vaultlite.errors import PolicyError


VALID_CAPABILITIES = {"read", "write", "delete", "list", "sudo"}

# Built-in policies
DEFAULT_POLICY = Policy(
    name="default",
    rules=[
        Rule(path="secret/*", capabilities=["read", "list"]),
        Rule(path="auth/token/lookup-self", capabilities=["read"]),
    ],
)

ROOT_POLICY = Policy(
    name="root",
    rules=[
        Rule(path="*", capabilities=["read", "write", "delete", "list", "sudo"]),
    ],
)


def validate_policy(policy: Policy) -> None:
    """Validate a policy definition.

    Raises:
        PolicyError: If the policy has invalid structure or capabilities.
    """
    if not policy.name:
        raise PolicyError("Policy must have a name")

    if not policy.rules:
        raise PolicyError(f"Policy '{policy.name}' has no rules")

    for rule in policy.rules:
        if not rule.path:
            raise PolicyError(f"Rule in policy '{policy.name}' has no path")
        invalid = set(rule.capabilities) - VALID_CAPABILITIES
        if invalid:
            raise PolicyError(
                f"Invalid capabilities in policy '{policy.name}': {invalid}"
            )


def _path_matches(pattern: str, path: str) -> bool:
    """Check if a path matches a pattern.

    Supports:
    - Exact match: "secret/data/db" matches "secret/data/db"
    - Glob: "secret/data/*" matches one level
    - Recursive glob: "secret/**" matches all levels
    - Star at root: "*" matches everything
    """
    if pattern == "*":
        return True

    # Convert ** to match any depth
    if "**" in pattern:
        # "secret/**" should match "secret/anything/deep/nested"
        base = pattern.replace("/**", "")
        if path == base or path.startswith(base + "/"):
            return True

    return fnmatch.fnmatch(path, pattern)


class PolicyManager:
    """Manages policies and evaluates access control decisions.

    Stores named policies and checks whether a set of policy names
    grants a specific capability on a specific path.
    """

    def __init__(self):
        self._policies: dict[str, Policy] = {
            "default": DEFAULT_POLICY,
            "root": ROOT_POLICY,
        }

    def add_policy(self, policy: Policy) -> None:
        """Add or update a named policy."""
        validate_policy(policy)
        self._policies[policy.name] = policy

    def get_policy(self, name: str) -> Optional[Policy]:
        """Get a policy by name. Returns None if not found."""
        return self._policies.get(name)

    def delete_policy(self, name: str) -> bool:
        """Delete a policy. Returns True if it existed.

        Cannot delete built-in policies (default, root).
        """
        if name in ("default", "root"):
            raise PolicyError(f"Cannot delete built-in policy: {name}")
        if name in self._policies:
            del self._policies[name]
            return True
        return False

    def list_policies(self) -> list[str]:
        """List all policy names."""
        return sorted(self._policies.keys())

    def check_access(
        self,
        policy_names: list[str],
        path: str,
        capability: str,
    ) -> bool:
        """Check if any of the given policies grants a capability on a path.

        Args:
            policy_names: List of policy names assigned to a token.
            path: The secret path being accessed.
            capability: The capability required (read/write/delete/list/sudo).

        Returns:
            True if access is granted, False if denied.
        """
        if capability not in VALID_CAPABILITIES:
            return False

        for name in policy_names:
            policy = self._policies.get(name)
            if policy is None:
                continue

            for rule in policy.rules:
                if _path_matches(rule.path, path):
                    if capability in rule.capabilities:
                        return True

        return False

    def get_capabilities(
        self, policy_names: list[str], path: str
    ) -> set[str]:
        """Get all capabilities granted on a path by the given policies."""
        caps: set[str] = set()

        for name in policy_names:
            policy = self._policies.get(name)
            if policy is None:
                continue
            for rule in policy.rules:
                if _path_matches(rule.path, path):
                    caps.update(rule.capabilities)

        return caps

    def to_dict(self) -> dict:
        """Serialize all policies for storage."""
        return {
            name: policy.to_dict()
            for name, policy in self._policies.items()
        }

    def load_from_dict(self, data: dict) -> None:
        """Load policies from serialized data."""
        for name, policy_data in data.items():
            policy = Policy.from_dict(policy_data)
            self._policies[name] = policy
