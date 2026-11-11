"""Central role-to-capability policy. Unknown values fail closed."""

from enum import StrEnum


class Role(StrEnum):
    VIEWER = "viewer"
    OPERATOR = "operator"
    ADMIN = "admin"


class Capability(StrEnum):
    DASHBOARD_READ = "dashboard:read"
    EXPLORER_READ = "explorer:read"
    EXPLORER_WRITE = "explorer:write"
    LOGS_READ = "logs:read"
    SERVICES_CONTROL = "services:control"
    CONTAINERS_CONTROL = "containers:control"
    POWER_CONTROL = "power:control"
    TERMINAL_ACCESS = "terminal:access"
    COMMANDS_EXECUTE = "commands:execute"
    CREDENTIALS_REVEAL = "credentials:reveal"
    SETTINGS_MANAGE = "settings:manage"
    USERS_MANAGE = "users:manage"


# Explorer remains usable for the user's own workspace. Its adapter must still
# canonicalize paths and reject traversal/symlink escapes.
_ROLE_CAPABILITIES = {
    Role.VIEWER: frozenset({
        Capability.DASHBOARD_READ, Capability.EXPLORER_READ,
        Capability.EXPLORER_WRITE, Capability.LOGS_READ,
    }),
    Role.OPERATOR: frozenset({
        Capability.DASHBOARD_READ, Capability.EXPLORER_READ,
        Capability.EXPLORER_WRITE, Capability.LOGS_READ,
    }),
    Role.ADMIN: frozenset(Capability),
}


def normalize_role(value: str | Role | None) -> Role | None:
    if isinstance(value, Role):
        return value
    if not isinstance(value, str):
        return None
    try:
        return Role(value.strip().lower())
    except ValueError:
        return None


def has_capability(role: str | Role | None, capability: str | Capability) -> bool:
    normalized_role = normalize_role(role)
    if normalized_role is None:
        return False
    try:
        normalized_capability = capability if isinstance(capability, Capability) else Capability(capability)
    except ValueError:
        return False
    return normalized_capability in _ROLE_CAPABILITIES[normalized_role]


def require_capability(role: str | Role | None, capability: str | Capability) -> None:
    if not has_capability(role, capability):
        raise PermissionError("Insufficient permissions")
