"""Verify an operator-pinned Decision Card and evaluate its scoped engine bundle.

The resulting bundle is derived from the signed card on every request. A bare
serialized ``policies[]`` bundle is not accepted as evidence of buyer approval.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from typing import Any

from policy_as_code_engine.card_attestation import CardAttestation, verify_card_attestation
from policy_as_code_engine.evaluator import PolicyEvaluator
from policy_as_code_engine.from_decision_card import policy_bundle_from_decision_card
from policy_as_code_engine.models import EvaluationContext, EvaluationResult, PolicyBundle


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Decision Card JSON contains a duplicate key")
        result[key] = value
    return result


def _invalid_constant(_value: str) -> None:
    raise ValueError("Decision Card JSON contains a non-finite number")


@dataclass(frozen=True)
class SignedCardGate:
    bundle: PolicyBundle
    vendor_id: str

    def evaluate(self) -> EvaluationResult:
        # No request-supplied identity, vendor, action, or condition assertions.
        # Conditional cards consequently deny until a trusted assertion channel
        # is implemented; this is intentional.
        context = EvaluationContext(action="use", resource={"vendor_id": self.vendor_id})
        return PolicyEvaluator().evaluate(self.bundle, context)


def load_signed_card_gate(
    envelope_json: str,
    *,
    buyer_id: str,
    buyer_key_url: str,
    buyer_public_key_b64: str,
    vendor_id: str,
) -> SignedCardGate:
    """Build the engine's bundle only from a signed card and pinned buyer key."""
    if not envelope_json or len(envelope_json.encode("utf-8")) > 131_072:
        raise ValueError("Decision Card envelope is missing or too large")
    if not buyer_id or not buyer_key_url.startswith("https://") or not vendor_id:
        raise ValueError("buyer and vendor pins are required")
    try:
        public_key = base64.b64decode(buyer_public_key_b64, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("buyer public key is invalid") from exc
    if len(public_key) != 32:
        raise ValueError("buyer public key must be 32 bytes")
    try:
        envelope = json.loads(
            envelope_json,
            object_pairs_hook=_unique_object,
            parse_constant=_invalid_constant,
        )
    except json.JSONDecodeError as exc:
        raise ValueError("Decision Card envelope is invalid JSON") from exc
    if not isinstance(envelope, dict) or set(envelope) != {"card", "attestation"}:
        raise ValueError("Decision Card envelope requires card and attestation")
    card = envelope["card"]
    if not isinstance(card, dict) or not isinstance(envelope["attestation"], dict):
        raise ValueError("Decision Card and attestation must be objects")
    buyer = card.get("buyer")
    subject = card.get("subject")
    if not isinstance(buyer, dict) or buyer.get("id") != buyer_id:
        raise ValueError("Decision Card buyer does not match the operator pin")
    if not isinstance(subject, dict) or subject.get("vendor_id") != vendor_id:
        raise ValueError("Decision Card vendor does not match the operator pin")
    attestation = CardAttestation.model_validate(envelope["attestation"])
    verify_card_attestation(
        card,
        attestation,
        trusted_key_url=buyer_key_url,
        trusted_public_key=public_key,
    )
    bundle = policy_bundle_from_decision_card(
        card,
        allowed_actions=["use"],
        attestation=attestation,
        trusted_key_url=buyer_key_url,
        trusted_public_key=public_key,
    )
    return SignedCardGate(bundle=bundle, vendor_id=vendor_id)
