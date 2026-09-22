"""Compare-time normalization: a versioned policy for what is volatile.

Recorded vectors stay raw. When replay compares a candidate's result with the
recorded one it applies THIS policy to both sides, so a timestamp the oracle
emitted at record time and the one the candidate emits at replay time compare
equal, and so a change to the policy never forces a re-record. Recording
provenance retains the version known at capture; the replay artifact separately
binds frozen config, source bytes and loaded implementation identity for the
policy executed during comparison.

Seven rules, in order:

1. Keys that Mongo-style document encoders add (``_id``, ``$oid``, ``$date``)
   are dropped: they are generated per insert and carry no behaviour.
2. A value under a volatile KEY NAME (timestamps, tokens, expiries, generated
   transaction ids: ``VOLATILE_KEY``) is replaced by ``<volatile>``, unless it
   is empty (``None``, ``""``, ``0``) -- an empty timestamp against a filled
   one is a real difference and stays visible.
3. A string VALUE shaped like a datetime (``DATETIME``) is replaced by
   ``<volatile-datetime>`` wherever it appears, because systems emit timestamps
   under names no key pattern anticipates.
4. A key named exactly ``mob_id`` or ``uuid`` whose value is a UUID is replaced
   by ``<volatile>``. The key stays in the object. A UUID under any other name,
   including a fixture company id, is compared as written. ``fax`` and
   ``status`` are not volatile. An equal UUID is never deleted to manufacture
   a match against a missing key.
5. When both sides are compared, a URL is replaced by ``<volatile>`` on both
   sides only when the host is ``127.0.0.1`` and the port is the only
   difference. A different scheme, path, query, or host stays visible.
6. When both sides are compared, a key named exactly ``password`` is replaced
   by ``<volatile>`` on both sides only when both values are 32 hexadecimal
   characters. An empty password, a short password, and any other key stay
   as written and still compare.
7. When both sides are compared, a URL is replaced by ``<volatile>`` on both
   sides when both are ``https://127.0.0.1`` with any port, the path
   ``/account/confirm-email``, and a non-empty ``verifyToken`` query value.
   The port and token value may differ. A different path, a different host,
   or a missing token stays visible.

The policy is idempotent: normalizing a normalized value changes nothing, which
is what lets both sides be normalized without worrying whether one already was.
Callers add exact key names with ``extra_volatile_keys`` for a consumer's own
generated fields; the built-in pattern is not widened per consumer.
"""

from __future__ import annotations

import hashlib
import json
import marshal
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

NORMALIZATION_VERSION = "v5"
POLICY_IDENTITY_V1 = "capcov-vector-comparison-policy/v1"
POLICY_IDENTITY_V2 = "capcov-vector-comparison-policy/v2"
POLICY_IDENTITY_V3 = "capcov-vector-comparison-policy/v3"
POLICY_IDENTITY_V4 = "capcov-vector-comparison-policy/v4"
POLICY_IDENTITY_FORMAT = "capcov-vector-comparison-policy/v5"

VOLATILE_KEY = re.compile(
    r"(_at$|_date$|^date|modified|created$|updated|timestamp|expires|token|^transaction$)", re.I
)
DATETIME = re.compile(
    r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$"
)
# Exact names only. participant_uuid and company_id are fixture identity.
GENERATED_ID_KEYS = frozenset({"mob_id", "uuid"})
UUID_VALUE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
LOOPBACK_URL = re.compile(
    r"^(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*)://127\.0\.0\.1:"
    r"(?P<port>[0-9]+)(?P<rest>[/?#].*)?$"
)
# Exact name. Only a 32-hex value on both sides is volatile.
PASSWORD_KEYS = frozenset({"password"})
HEX32_VALUE = re.compile(r"^[0-9a-fA-F]{32}$")
# Exact confirm-email shape. Port and verifyToken may differ; the token must
# be present. A different path, host, or a missing token is not this shape.
CONFIRM_EMAIL_URL = re.compile(
    r"^https://127\.0\.0\.1:(?P<port>[0-9]+)"
    r"/account/confirm-email\?verifyToken=(?P<token>[^&#]+)$"
)
DROPPED_KEYS = frozenset({"_id", "$oid", "$date"})

MASK_VOLATILE = "<volatile>"
MASK_DATETIME = "<volatile-datetime>"
_align_compared = None

try:
    # Pin the module location and bytes observed during import. Replay checks
    # that this source has not drifted before publishing artifacts; the policy
    # identity also fingerprints the actual loaded normalizer code objects.
    _IMPORTED_SOURCE_PATH = Path(__file__).resolve()
    _IMPORTED_SOURCE_SHA256 = hashlib.sha256(_IMPORTED_SOURCE_PATH.read_bytes()).hexdigest()
except OSError:
    _IMPORTED_SOURCE_PATH = None
    _IMPORTED_SOURCE_SHA256 = None


def _json_sha256(value) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class FrozenComparisonPolicy:
    """One replay's immutable normalization config and bound implementation."""

    normalization_version: str
    volatile_key_pattern: str
    volatile_key_flags: int
    datetime_pattern: str
    datetime_flags: int
    dropped_keys: frozenset[str]
    mask_volatile: str
    mask_datetime: str
    preserved_empty_volatile_values: tuple
    extra_volatile_keys: frozenset[str]
    generated_id_keys: frozenset[str]
    uuid_value_pattern: str
    uuid_value_flags: int
    loopback_url_pattern: str
    loopback_url_flags: int
    password_keys: frozenset[str]
    hex32_value_pattern: str
    hex32_value_flags: int
    confirm_email_url_pattern: str
    confirm_email_url_flags: int
    source_sha256: str
    implementation_sha256: str
    python_implementation: str
    python_version: str
    _normalizer: object = field(repr=False, compare=False)
    _align: object = field(repr=False, compare=False)

    def normalize(self, value):
        """Apply the closure built from this policy's frozen values."""
        return self._normalizer(value)

    def align(self, left, right):
        """Mask paired volatile values on both sides without dropping keys."""
        return self._align(left, right)

    def identity(self) -> dict:
        config = {
            "normalization_version": self.normalization_version,
            "volatile_key_pattern": self.volatile_key_pattern,
            "volatile_key_flags": self.volatile_key_flags,
            "datetime_pattern": self.datetime_pattern,
            "datetime_flags": self.datetime_flags,
            "dropped_keys": sorted(self.dropped_keys),
            "mask_volatile": self.mask_volatile,
            "mask_datetime": self.mask_datetime,
            "preserved_empty_volatile_values": list(self.preserved_empty_volatile_values),
            "extra_volatile_keys": sorted(self.extra_volatile_keys),
            "generated_id_keys": sorted(self.generated_id_keys),
            "uuid_value_pattern": self.uuid_value_pattern,
            "uuid_value_flags": self.uuid_value_flags,
            "loopback_url_pattern": self.loopback_url_pattern,
            "loopback_url_flags": self.loopback_url_flags,
            "password_keys": sorted(self.password_keys),
            "hex32_value_pattern": self.hex32_value_pattern,
            "hex32_value_flags": self.hex32_value_flags,
            "confirm_email_url_pattern": self.confirm_email_url_pattern,
            "confirm_email_url_flags": self.confirm_email_url_flags,
            "python_implementation": self.python_implementation,
            "python_version": self.python_version,
        }
        core = {
            "format": POLICY_IDENTITY_FORMAT,
            "normalization_version": self.normalization_version,
            "source_sha256": self.source_sha256,
            "implementation_sha256": self.implementation_sha256,
            "config": config,
            "config_sha256": _json_sha256(config),
        }
        return {**core, "policy_sha256": _json_sha256(core)}


def freeze_comparison_policy(extra_volatile_keys=()) -> FrozenComparisonPolicy:
    """Snapshot module config and bind a recursive normalizer to that snapshot.

    The returned closure never reads the mutable module globals again. Its code
    objects are hashed separately from the import-time source bytes, so cached
    bytecode is described as loaded; drift of the source file since import is
    refused before replay publication. This is bookkeeping, not authentication.
    """
    global _align_compared
    if _IMPORTED_SOURCE_SHA256 is None:
        raise RuntimeError("cannot identify the imported comparison-policy source")
    version = NORMALIZATION_VERSION
    volatile_pattern, volatile_flags = VOLATILE_KEY.pattern, int(VOLATILE_KEY.flags)
    datetime_pattern, datetime_flags = DATETIME.pattern, int(DATETIME.flags)
    uuid_pattern, uuid_flags = UUID_VALUE.pattern, int(UUID_VALUE.flags)
    loopback_pattern, loopback_flags = LOOPBACK_URL.pattern, int(LOOPBACK_URL.flags)
    hex32_pattern, hex32_flags = HEX32_VALUE.pattern, int(HEX32_VALUE.flags)
    confirm_pattern, confirm_flags = CONFIRM_EMAIL_URL.pattern, int(CONFIRM_EMAIL_URL.flags)
    dropped_keys = frozenset(DROPPED_KEYS)
    generated_keys = frozenset(GENERATED_ID_KEYS)
    password_keys = frozenset(PASSWORD_KEYS)
    mask_volatile, mask_datetime = MASK_VOLATILE, MASK_DATETIME
    preserved_empty = (None, "", 0)
    extra = frozenset(extra_volatile_keys)
    # Bind builtins and the compiled patterns to the closures too. Fixture and
    # endpoint callbacks cannot change this run by changing module globals.
    is_instance = isinstance
    to_bool = bool
    dict_type, list_type, tuple_type, str_type = dict, list, tuple, str
    volatile_re = re.compile(volatile_pattern, volatile_flags)
    datetime_re = re.compile(datetime_pattern, datetime_flags)
    uuid_re = re.compile(uuid_pattern, uuid_flags)
    loopback_re = re.compile(loopback_pattern, loopback_flags)
    hex32_re = re.compile(hex32_pattern, hex32_flags)
    confirm_re = re.compile(confirm_pattern, confirm_flags)

    def key_is_volatile(key):
        if not is_instance(key, str_type):
            return False
        return to_bool(volatile_re.search(key)) or key in extra

    def value_is_uuid(item):
        return is_instance(item, str_type) and to_bool(uuid_re.match(item))

    def value_is_hex32(item):
        return is_instance(item, str_type) and to_bool(hex32_re.match(item))

    def normalize_value(value):
        if is_instance(value, dict_type):
            out = {}
            for key, item in value.items():
                if key in dropped_keys:
                    continue
                if key_is_volatile(key) and item not in preserved_empty:
                    out[key] = mask_volatile
                elif key in generated_keys and value_is_uuid(item):
                    # Keep the key. Deleting an equal UUID would make a missing
                    # key on the other side compare equal.
                    out[key] = mask_volatile
                else:
                    out[key] = normalize_value(item)
            return out
        if is_instance(value, list_type):
            return [normalize_value(item) for item in value]
        if is_instance(value, tuple_type):
            return [normalize_value(item) for item in value]
        if is_instance(value, str_type) and datetime_re.match(value):
            return mask_datetime
        return value

    def ports_only(left, right):
        left_url = loopback_re.match(left)
        right_url = loopback_re.match(right)
        if left_url is None or right_url is None:
            return False
        same_rest = (left_url.group("rest") or "") == (right_url.group("rest") or "")
        return (left_url.group("scheme") == right_url.group("scheme") and same_rest
                and left_url.group("port") != right_url.group("port"))

    def confirm_email_tokens(left, right):
        # Both sides are the confirm-email URL. The token value is not compared.
        return to_bool(confirm_re.match(left)) and to_bool(confirm_re.match(right))

    def align_pair(left, right):
        if is_instance(left, dict_type) and is_instance(right, dict_type):
            out_left, out_right = {}, {}
            for key in set(left) | set(right):
                if key not in right:
                    out_left[key] = left[key]
                    continue
                if key not in left:
                    out_right[key] = right[key]
                    continue
                left_item, right_item = left[key], right[key]
                if key in generated_keys and value_is_uuid(left_item) and value_is_uuid(right_item):
                    out_left[key] = mask_volatile
                    out_right[key] = mask_volatile
                    continue
                if key in password_keys and value_is_hex32(left_item) and value_is_hex32(right_item):
                    out_left[key] = mask_volatile
                    out_right[key] = mask_volatile
                    continue
                paired_left, paired_right = align_pair(left_item, right_item)
                out_left[key] = paired_left
                out_right[key] = paired_right
            return out_left, out_right
        if is_instance(left, list_type) and is_instance(right, list_type):
            shared = min(len(left), len(right))
            paired = [align_pair(left[index], right[index]) for index in range(shared)]
            return ([item[0] for item in paired] + list(left[shared:]),
                    [item[1] for item in paired] + list(right[shared:]))
        if (is_instance(left, str_type) and is_instance(right, str_type)
                and (ports_only(left, right) or confirm_email_tokens(left, right))):
            return mask_volatile, mask_volatile
        return left, right

    implementation = hashlib.sha256(
        marshal.dumps(key_is_volatile.__code__)
        + marshal.dumps(value_is_uuid.__code__)
        + marshal.dumps(value_is_hex32.__code__)
        + marshal.dumps(normalize_value.__code__)
        + marshal.dumps(ports_only.__code__)
        + marshal.dumps(confirm_email_tokens.__code__)
        + marshal.dumps(align_pair.__code__)
    ).hexdigest()
    _align_compared = align_pair
    return FrozenComparisonPolicy(
        normalization_version=version,
        volatile_key_pattern=volatile_pattern,
        volatile_key_flags=volatile_flags,
        datetime_pattern=datetime_pattern,
        datetime_flags=datetime_flags,
        dropped_keys=dropped_keys,
        mask_volatile=mask_volatile,
        mask_datetime=mask_datetime,
        preserved_empty_volatile_values=preserved_empty,
        extra_volatile_keys=extra,
        generated_id_keys=generated_keys,
        uuid_value_pattern=uuid_pattern,
        uuid_value_flags=uuid_flags,
        loopback_url_pattern=loopback_pattern,
        loopback_url_flags=loopback_flags,
        password_keys=password_keys,
        hex32_value_pattern=hex32_pattern,
        hex32_value_flags=hex32_flags,
        confirm_email_url_pattern=confirm_pattern,
        confirm_email_url_flags=confirm_flags,
        source_sha256=_IMPORTED_SOURCE_SHA256,
        implementation_sha256=implementation,
        python_implementation=sys.implementation.name,
        python_version=sys.version.split()[0],
        _normalizer=normalize_value,
        _align=align_pair,
    )


def assert_comparison_policy_source_unchanged(policy: FrozenComparisonPolicy) -> None:
    """Refuse replay publication if the imported source file drifted mid-run."""
    if _IMPORTED_SOURCE_PATH is None:
        raise RuntimeError("cannot verify the imported comparison-policy source")
    try:
        current = hashlib.sha256(_IMPORTED_SOURCE_PATH.read_bytes()).hexdigest()
    except OSError as exc:
        raise RuntimeError("cannot verify the imported comparison-policy source") from exc
    if current != _IMPORTED_SOURCE_SHA256 or policy.source_sha256 != _IMPORTED_SOURCE_SHA256:
        raise RuntimeError("comparison-policy source changed since import; refusing replay artifact publication")


def comparison_policy_identity() -> dict:
    """Describe a frozen default policy (local execution disclosure only)."""
    return freeze_comparison_policy().identity()


def validate_comparison_policy_identity(identity) -> bool:
    """Check a replay's source/config identity for exact shape and self-consistency.

    Historical replay artifacts are not compared with today's normalizer. The
    recorded identity is a local execution disclosure, not an authenticated
    attestation of which code actually ran.
    """
    if not isinstance(identity, dict):
        return False
    identity_format = identity.get("format")
    if identity_format == POLICY_IDENTITY_V1:
        fields = {"format", "normalization_version", "source_sha256", "config",
                  "config_sha256", "policy_sha256"}
        config_fields = {
            "normalization_version", "volatile_key_pattern", "volatile_key_flags",
            "datetime_pattern", "datetime_flags", "dropped_keys", "mask_volatile",
            "mask_datetime", "preserved_empty_volatile_values", "extra_volatile_keys",
        }
    elif identity_format in (POLICY_IDENTITY_V2, POLICY_IDENTITY_V3, POLICY_IDENTITY_V4,
                             POLICY_IDENTITY_FORMAT):
        fields = {"format", "normalization_version", "source_sha256", "implementation_sha256",
                  "config", "config_sha256", "policy_sha256"}
        config_fields = {
            "normalization_version", "volatile_key_pattern", "volatile_key_flags",
            "datetime_pattern", "datetime_flags", "dropped_keys", "mask_volatile",
            "mask_datetime", "preserved_empty_volatile_values", "extra_volatile_keys",
            "python_implementation", "python_version",
        }
        if identity_format in (POLICY_IDENTITY_V3, POLICY_IDENTITY_V4, POLICY_IDENTITY_FORMAT):
            config_fields = config_fields | {
                "generated_id_keys", "uuid_value_pattern", "uuid_value_flags",
                "loopback_url_pattern", "loopback_url_flags",
            }
        if identity_format in (POLICY_IDENTITY_V4, POLICY_IDENTITY_FORMAT):
            config_fields = config_fields | {
                "password_keys", "hex32_value_pattern", "hex32_value_flags",
            }
        if identity_format == POLICY_IDENTITY_FORMAT:
            config_fields = config_fields | {
                "confirm_email_url_pattern", "confirm_email_url_flags",
            }
    else:
        return False
    if set(identity) != fields:
        return False
    version = identity.get("normalization_version")
    source_digest = identity.get("source_sha256")
    implementation_digest = identity.get("implementation_sha256")
    config = identity.get("config")
    if (not isinstance(version, str) or not version
            or not isinstance(source_digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", source_digest) is None):
        return False
    if (identity_format in (POLICY_IDENTITY_V2, POLICY_IDENTITY_V3, POLICY_IDENTITY_V4,
                            POLICY_IDENTITY_FORMAT)
            and (not isinstance(implementation_digest, str)
                 or re.fullmatch(r"[0-9a-f]{64}", implementation_digest) is None)):
        return False
    if not isinstance(config, dict) or set(config) != config_fields:
        return False
    if (config.get("normalization_version") != version
            or not isinstance(config.get("volatile_key_pattern"), str)
            or type(config.get("volatile_key_flags")) is not int
            or not isinstance(config.get("datetime_pattern"), str)
            or type(config.get("datetime_flags")) is not int
            or not isinstance(config.get("dropped_keys"), list)
            or any(not isinstance(item, str) for item in config["dropped_keys"])
            or not isinstance(config.get("mask_volatile"), str)
            or not isinstance(config.get("mask_datetime"), str)
            or not isinstance(config.get("preserved_empty_volatile_values"), list)
            or not isinstance(config.get("extra_volatile_keys"), list)
            or any(not isinstance(item, str) for item in config["extra_volatile_keys"])
            or (identity_format in (POLICY_IDENTITY_V2, POLICY_IDENTITY_V3, POLICY_IDENTITY_V4,
                                    POLICY_IDENTITY_FORMAT)
                and (not isinstance(config.get("python_implementation"), str)
                     or not config["python_implementation"]
                     or not isinstance(config.get("python_version"), str)
                     or not config["python_version"]))
            or (identity_format in (POLICY_IDENTITY_V3, POLICY_IDENTITY_V4, POLICY_IDENTITY_FORMAT)
                and (not isinstance(config.get("generated_id_keys"), list)
                     or any(not isinstance(item, str) for item in config["generated_id_keys"])
                     or not isinstance(config.get("uuid_value_pattern"), str)
                     or type(config.get("uuid_value_flags")) is not int
                     or not isinstance(config.get("loopback_url_pattern"), str)
                     or type(config.get("loopback_url_flags")) is not int))
            or (identity_format in (POLICY_IDENTITY_V4, POLICY_IDENTITY_FORMAT)
                and (not isinstance(config.get("password_keys"), list)
                     or any(not isinstance(item, str) for item in config["password_keys"])
                     or not isinstance(config.get("hex32_value_pattern"), str)
                     or type(config.get("hex32_value_flags")) is not int))
            or (identity_format == POLICY_IDENTITY_FORMAT
                and (not isinstance(config.get("confirm_email_url_pattern"), str)
                     or type(config.get("confirm_email_url_flags")) is not int))):
        return False
    config_digest = identity.get("config_sha256")
    policy_digest = identity.get("policy_sha256")
    if any(not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None
           for value in (config_digest, policy_digest)):
        return False
    if _json_sha256(config) != config_digest:
        return False
    core = {key: value for key, value in identity.items() if key != "policy_sha256"}
    return _json_sha256(core) == policy_digest


def align_compared(left, right):
    """Return both sides with paired volatile values masked.

    Uses the aligner captured by the most recent frozen policy. Keys are never
    removed: an equal ``mob_id`` or ``uuid`` becomes ``<volatile>`` in place,
    a ``password`` that is 32 hex characters on both sides does too, and so
    does an ``https://127.0.0.1`` confirm-email URL with a ``verifyToken``.
    """
    if _align_compared is None:
        freeze_comparison_policy()
    return _align_compared(left, right)


def is_volatile_key(key: object, extra_volatile_keys: tuple[str, ...] | frozenset[str] = ()) -> bool:
    """Whether a dict key names a volatile value under this policy."""
    if not isinstance(key, str):
        return False
    return bool(VOLATILE_KEY.search(key)) or key in extra_volatile_keys


def normalize(value, extra_volatile_keys=()):
    """Apply the policy to ``value`` recursively; returns a new structure."""
    return freeze_comparison_policy(extra_volatile_keys).normalize(value)
