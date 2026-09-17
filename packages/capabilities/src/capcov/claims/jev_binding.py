"""Content-addressed binding of a Jev advisory to an authoritative judge run.

The binding is provenance, not authority.  It records which exact advisory was
available beside which exact deterministic judgment, but never changes the
judgment's verdict or exit code and exports no claim facts or rules.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from . import jev


ARTIFACT_KIND = "capcov-jev-judge-binding-v1"
ALLOWED_EXIT_CODES = {0, 1, 5}


def _object(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise jev.JevError("invalid-input", f"{path} must be an object")
    return value


def _text(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value:
        raise jev.JevError("invalid-input", f"{path} must be nonempty")
    return value


def _digest(value: Any, path: str) -> str:
    value = _text(value, path)
    if len(value) != 64 or value != value.lower():
        raise jev.JevError("invalid-input", f"{path} must be a lowercase sha256 digest")
    try:
        int(value, 16)
    except ValueError as exc:
        raise jev.JevError("invalid-input", f"{path} must be a lowercase sha256 digest") from exc
    return value


def _judge_identity(judge: Mapping[str, Any]) -> dict[str, Any]:
    if judge.get("schema") != "capcov-compiled-judge-v1":
        raise jev.JevError("invalid-input", "judge must be capcov-compiled-judge-v1")
    receipt = _object(judge.get("receipt"), "judge.receipt")
    pack = _object(judge.get("pack"), "judge.pack")
    kernels = _object(judge.get("kernels"), "judge.kernels")
    if kernels.get("matched") is not True or kernels.get("closure_digest_equal") is not True:
        raise jev.JevError("invalid-input", "judge kernels must agree before an advisory is bound")
    semantic_digests = [_digest(kernels.get(name), f"judge.kernels.{name}") for name in (
        "python_digest", "souffle_digest", "compiled_digest")]
    if len(set(semantic_digests)) != 1:
        raise jev.JevError("invalid-input", "judge kernel semantic digests must be identical")
    closure_digests = [_digest(kernels.get(name), f"judge.kernels.{name}") for name in (
        "souffle_closure_digest", "compiled_closure_digest", "closure_digest")]
    if len(set(closure_digests)) != 1:
        raise jev.JevError("invalid-input", "judge Souffle closure digests must be identical")
    exit_code = judge.get("exit_code")
    if type(exit_code) is not int or exit_code not in ALLOWED_EXIT_CODES:
        raise jev.JevError("invalid-input", "judge.exit_code must be 0, 1, or 5")
    verdict = _text(judge.get("verdict"), "judge.verdict")
    expected = {0: "supported", 1: "not-supported", 5: "pending-premise"}[exit_code]
    if verdict != expected:
        raise jev.JevError("invalid-input", "judge verdict and exit code disagree")
    ops = _object(judge.get("ops"), "judge.ops")
    certificates: dict[str, str | None] = {}
    for op, entry in sorted(ops.items()):
        if not isinstance(op, str) or not op:
            raise jev.JevError("invalid-input", "judge op names must be nonempty")
        entry = _object(entry, f"judge.ops.{op}")
        certificate = entry.get("certificate_sha256")
        certificates[op] = None if certificate is None else _digest(
            certificate, f"judge.ops.{op}.certificate_sha256")
    required_ops = judge.get("required_ops")
    if (not isinstance(required_ops, list)
            or any(not isinstance(op, str) or not op for op in required_ops)):
        raise jev.JevError("invalid-input", "judge.required_ops must be an array of names")
    return {
        "run": _text(receipt.get("run"), "judge.receipt.run"),
        "model_digest": _digest(receipt.get("model"), "judge.receipt.model"),
        "snapshot_digest": _digest(receipt.get("snapshot"), "judge.receipt.snapshot"),
        "rule_pack_id": _text(pack.get("id"), "judge.pack.id"),
        "rule_program_digest": _digest(
            pack.get("program_digest"), "judge.pack.program_digest"),
        "kernel_semantics_digest": semantic_digests[0],
        "closure_digest": closure_digests[0],
        "certificate_digests": certificates,
        "required_ops": list(required_ops),
        "verdict": verdict,
        "exit_code": exit_code,
    }


def bind(advisory: Mapping[str, Any], judge: Mapping[str, Any]) -> dict[str, Any]:
    """Bind exact advisory and judge documents without changing authority."""
    if advisory.get("kind") not in {jev.ARTIFACT_KIND, "capcov-jev-pattern-sensitivity-v1"}:
        raise jev.JevError("invalid-input", "unsupported Jev advisory kind")
    if advisory.get("kind") == jev.ARTIFACT_KIND:
        jev.claims_bundle(advisory)
    else:
        # Import here to keep the generic Jev module below its pattern adapter.
        from . import jev_patterns
        jev_patterns.claims_bundle(advisory)
    identity = _judge_identity(judge)
    core = {
        "schema_version": 1,
        "kind": ARTIFACT_KIND,
        "producer": {"class": "binding", "source": "capcov deterministic jev-judge-binding-v1"},
        "advisory": {
            "kind": advisory["kind"],
            "assessment_id": advisory["assessment_id"],
            "sha256": jev._digest(jev._plain_json(advisory, "advisory")),
        },
        "judge": {**identity, "sha256": jev._digest(jev._plain_json(judge, "judge"))},
        "authority": {
            "advisory_may_rank_or_request_probe": True,
            "advisory_may_change_verdict": False,
            "advisory_may_change_exit_code": False,
            "advisory_may_satisfy_missing_premise": False,
            "advisory_may_qualify_claim": False,
            "authoritative_source": "judge",
        },
    }
    core["binding_id"] = f"jev-judge:{jev._digest(core)}"
    return core


def validate(binding: Mapping[str, Any], advisory: Mapping[str, Any],
             judge: Mapping[str, Any]) -> None:
    """Require a binding to be exactly reproducible from both input artifacts."""
    if not isinstance(binding, Mapping) or binding != bind(advisory, judge):
        raise jev.JevError("invalid-input", "binding does not match the advisory and judge")
