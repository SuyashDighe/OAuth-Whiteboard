"""Cryptographically signed, short-lived, user-bound OAuth state management.

Protects against:
- Cross-Site Request Forgery (CSRF)
- OAuth Authorization Code Replay Attacks
- Account-Connection Mix-up Attacks (binding state to specific user_id)
"""

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Dict, Set, Tuple
from app.config import get_settings


class StateError(Exception):
    """Base exception for OAuth state errors."""
    pass


class InvalidStateError(StateError):
    """Raised when the state token is malformed, has an invalid signature, or wrong user."""
    pass


class ExpiredStateError(StateError):
    """Raised when the state token has exceeded its TTL."""
    pass


class StateReplayError(StateError):
    """Raised when an OAuth state or nonce is submitted more than once."""
    pass


class OAuthStateManager:
    """Generates and validates HMAC-SHA256 signed OAuth state tokens.

    Format: <base64url(payload)>.<base64url(hmac_signature)>
    Payload contains:
      - user_id: ID of the user who initiated the flow
      - nonce: Cryptographic random bytes
      - issued_at: UNIX timestamp
      - purpose: "google_oauth"
    """

    def __init__(self, secret_key: str, ttl_seconds: int = 600):
        self._secret = secret_key.encode("utf-8")
        self._ttl_seconds = ttl_seconds
        # In-memory consumed nonces tracking with timestamp for automatic pruning
        self._consumed_nonces: Dict[str, float] = {}

    def _prune_expired_nonces(self) -> None:
        """Remove nonces older than TTL to prevent memory leaks."""
        cutoff = time.time() - (self._ttl_seconds * 2)
        expired_keys = [k for k, ts in self._consumed_nonces.items() if ts < cutoff]
        for k in expired_keys:
            self._consumed_nonces.pop(k, None)

    def generate_state(self, user_id: str) -> str:
        """Create a signed, time-limited state string bound to user_id.

        Args:
            user_id: Authenticated application user ID.

        Returns:
            URL-safe state string.
        """
        self._prune_expired_nonces()
        payload = {
            "user_id": user_id,
            "nonce": secrets.token_hex(16),
            "issued_at": int(time.time()),
            "purpose": "google_oauth",
        }
        payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode("utf-8").rstrip("=")

        # Compute HMAC signature
        sig = hmac.new(self._secret, payload_b64.encode("utf-8"), hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).decode("utf-8").rstrip("=")

        return f"{payload_b64}.{sig_b64}"

    def validate_state(self, state_str: str, expected_user_id: str) -> Dict:
        """Validate state token signature, age, user match, and replay prevention.

        Args:
            state_str: State string from callback.
            expected_user_id: ID of user making the callback request.

        Returns:
            Dict containing original state payload.

        Raises:
            InvalidStateError: Tampered signature, malformed token, or user mismatch.
            ExpiredStateError: State older than TTL.
            StateReplayError: State nonce already used.
        """
        self._prune_expired_nonces()

        if not state_str or "." not in state_str:
            raise InvalidStateError("OAuth state parameter is missing or malformed.")

        parts = state_str.split(".", 1)
        payload_b64, sig_b64 = parts[0], parts[1]

        # Verify HMAC signature
        expected_sig = hmac.new(self._secret, payload_b64.encode("utf-8"), hashlib.sha256).digest()
        expected_sig_b64 = base64.urlsafe_b64encode(expected_sig).decode("utf-8").rstrip("=")

        if not hmac.compare_digest(sig_b64, expected_sig_b64):
            raise InvalidStateError("Invalid state signature: State has been tampered with or corrupted.")

        # Decode payload
        try:
            # Pad base64 string
            padded_payload = payload_b64 + "=" * (-len(payload_b64) % 4)
            payload_bytes = base64.urlsafe_b64decode(padded_payload)
            payload = json.loads(payload_bytes.decode("utf-8"))
        except Exception as exc:
            raise InvalidStateError(f"Failed to parse state payload: {exc}") from exc

        # Check payload fields
        if payload.get("purpose") != "google_oauth":
            raise InvalidStateError("Invalid state purpose.")

        # Check expiration
        issued_at = payload.get("issued_at", 0)
        now = time.time()
        if now - issued_at > self._ttl_seconds:
            raise ExpiredStateError(
                f"OAuth state has expired (TTL is {self._ttl_seconds} seconds). Please initiate authorization again."
            )
        if issued_at > now + 60:  # Allow 1 minute clock skew
            raise InvalidStateError("OAuth state issued in the future.")

        # Account connection mix-up prevention:
        state_user_id = payload.get("user_id")
        if not state_user_id or state_user_id != expected_user_id:
            raise InvalidStateError(
                f"State user mismatch: State belongs to '{state_user_id}', but current request user is '{expected_user_id}'. "
                "Possible account connection mix-up attempt."
            )

        # Anti-replay: single-use nonce
        nonce = payload.get("nonce")
        if not nonce:
            raise InvalidStateError("State missing nonce.")

        if nonce in self._consumed_nonces:
            raise StateReplayError("OAuth state has already been used. Authorization code replay is prohibited.")

        # Record consumed nonce
        self._consumed_nonces[nonce] = now

        return payload


_state_manager: OAuthStateManager | None = None


def get_state_manager() -> OAuthStateManager:
    """Singleton state manager dependency."""
    global _state_manager
    if _state_manager is None:
        settings = get_settings()
        _state_manager = OAuthStateManager(
            secret_key=settings.SECRET_KEY.get_secret_value(),
            ttl_seconds=settings.OAUTH_STATE_TTL_SECONDS,
        )
    return _state_manager
