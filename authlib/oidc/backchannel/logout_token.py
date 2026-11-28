"""Logout token creation for OIDC Back-Channel Logout 1.0.

https://openid.net/specs/openid-connect-backchannel-1_0.html
"""

import time
import uuid

from joserfc import jwt
from joserfc.errors import InvalidClaimError
from joserfc.errors import MissingClaimError
from joserfc.jwk import KeySet
from joserfc.jwk import import_key
from joserfc.jws import JWSRegistry

from authlib.oauth2.claims import JWTClaims

BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"


class LogoutTokenClaims(JWTClaims):
    """Claims of a validated OpenID Connect logout token.

    The validation rules come from `OpenID Connect Back-Channel Logout 1.0`_
    section 2.4 and 2.6.

    .. _OpenID Connect Back-Channel Logout 1.0:
        https://openid.net/specs/openid-connect-backchannel-1_0.html
    """

    ESSENTIAL_CLAIMS = ["iss", "aud", "iat", "exp", "jti", "events"]
    REGISTERED_CLAIMS = JWTClaims.REGISTERED_CLAIMS + ["events", "sid"]
    CLAIM_TYPES = {
        "iss": str,
        "sub": str,
        "aud": (str, list),
        "iat": (int, float),
        "exp": (int, float),
        "jti": str,
        "sid": str,
        "events": dict,
        "nonce": str,
    }

    def validate(self, now=None, leeway=0):
        for key in self.ESSENTIAL_CLAIMS:
            if key not in self:
                raise MissingClaimError(key)

        # backchannel §2.4: "nonce - PROHIBITED. A nonce Claim MUST NOT be
        # present in a Logout Token. Its presence indicates an error."
        if "nonce" in self:
            raise InvalidClaimError("nonce")

        if "sub" not in self and "sid" not in self:
            # backchannel §2.4: "A Logout Token MUST contain either a sub or a
            # sid Claim, and MAY contain both."
            raise MissingClaimError("sub or sid")

        super().validate(now=now, leeway=leeway)
        self.validate_events()
        self.validate_aud()
        self.validate_issued_at(now, leeway)

    def validate_events(self):
        # backchannel §2.4: "events - REQUIRED. Claim whose value is a JSON
        # object containing the member name
        # http://schemas.openid.net/event/backchannel-logout. [...] The
        # corresponding member value MUST be a JSON object and SHOULD be the
        # empty JSON object {}."
        events = self.get("events")
        if not isinstance(events, dict):
            raise InvalidClaimError("events")

        event = events.get(BACKCHANNEL_LOGOUT_EVENT)
        if not isinstance(event, dict):
            raise InvalidClaimError("events")

    def validate_aud(self):
        client_id = self.params.get("client_id")
        if not client_id:
            return

        aud = self.get("aud")
        audiences = aud if isinstance(aud, list) else [aud]
        accepted = client_id if isinstance(client_id, list) else [client_id]
        if not any(value in audiences for value in accepted):
            raise InvalidClaimError("aud")

    def validate_issued_at(self, now=None, leeway=0):
        max_age = self.params.get("max_age")
        if max_age is None:
            return

        if now is None:
            now = int(time.time())
        if now - self["iat"] > max_age + leeway:
            raise InvalidClaimError("iat")


def create_logout_token(
    issuer: str,
    audience: str,
    key,
    algorithm: str = "RS256",
    sub: str | None = None,
    sid: str | None = None,
    expires_in: int = 120,
) -> str:
    """Create a signed logout token JWT.

    :param issuer: The OP's issuer identifier.
    :param audience: The client_id of the RP being notified.
    :param key: The signing key (joserfc Key, KeySet, JWK dict, or JWKS dict).
    :param algorithm: JWT signing algorithm.
    :param sub: Subject identifier. Required if ``sid`` is not provided.
    :param sid: Session ID. Required if ``sub`` is not provided.
    :param expires_in: Token lifetime in seconds. Spec recommends at most 120.
    :raises ValueError: If neither ``sub`` nor ``sid`` is provided, or if
        ``algorithm`` is ``none``.
    """
    # backchannel §2.4: "A Logout Token MUST contain either a sub or a sid
    # Claim, and MAY contain both."
    if sub is None and sid is None:
        raise ValueError("At least one of 'sub' or 'sid' must be provided")

    # backchannel §2.6: "Additionally, an alg with the value none MUST NOT be
    # used for Logout Tokens."
    if algorithm == "none":
        raise ValueError("Logout tokens must not use the 'none' algorithm")

    now = int(time.time())
    payload: dict = {
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "exp": now + expires_in,
        "jti": str(uuid.uuid4()),
        # backchannel §2.4: "events - REQUIRED. Claim whose value is a JSON
        # object containing the member name
        # http://schemas.openid.net/event/backchannel-logout. [...] The
        # corresponding member value MUST be a JSON object and SHOULD be the
        # empty JSON object {}."
        "events": {BACKCHANNEL_LOGOUT_EVENT: {}},
    }

    if sub is not None:
        payload["sub"] = sub
    if sid is not None:
        payload["sid"] = sid

    # backchannel §2.4: "It is RECOMMENDED that Logout Tokens be explicitly
    # typed. This is accomplished by including a typ (type) Header Parameter
    # with a value of logout+jwt in the Logout Token."
    header = {"alg": algorithm, "typ": "logout+jwt"}

    if isinstance(key, dict):
        if "keys" in key:
            key = KeySet.import_key_set(key)  # type: ignore[arg-type]
        else:
            key = import_key(key)

    if not isinstance(key, KeySet) and key.kid:
        header["kid"] = key.kid

    return jwt.encode(header, payload, key, algorithms=[algorithm])


def _import_verification_key(key):
    if isinstance(key, dict):
        if "keys" in key:
            return KeySet.import_key_set(key)  # type: ignore[arg-type]
        return import_key(key)
    return key


def _get_verification_algorithms(key, algorithms):
    if algorithms is None:
        if isinstance(key, KeySet):
            algorithms = [alg.name for alg in JWSRegistry.filter_algorithms(key)]
        elif getattr(key, "alg", None):
            algorithms = [key.alg]

    if algorithms is None:
        return None

    algorithms = [alg for alg in algorithms if alg != "none"]
    if not algorithms:
        raise InvalidClaimError("alg")
    return algorithms


def validate_logout_token(
    token: str,
    key=None,
    issuer: str | None = None,
    audience: str | list[str] | None = None,
    *,
    jwks=None,
    client_id: str | None = None,
    algorithms: list[str] | None = None,
    leeway: int = 120,
    now: int | None = None,
    max_age: int | None = None,
    claims_options: dict | None = None,
) -> LogoutTokenClaims:
    """Validate a signed OpenID Connect logout token.

    This validates the signature, the ``iss``, ``aud``, ``iat`` and ``exp``
    claims, the back-channel logout event, and rejects a ``nonce`` claim.
    It does not consume the ``jti`` claim: replay protection needs a state
    store, which is the responsibility of the caller. See
    :class:`~authlib.oidc.backchannel.BackchannelLogoutReceiver`.

    :param token: The compact serialized logout token.
    :param key: The key, key set, JWK dict or JWKS dict of the issuer.
    :param issuer: The expected issuer, when it is known.
    :param audience: The expected audience, usually the client ID.
    :param jwks: Alias for ``key``.
    :param client_id: Alias for ``audience``.
    :param algorithms: The accepted signing algorithms. ``none`` is always
        rejected.
    :param leeway: The allowed clock skew, in seconds.
    :param now: The current timestamp, for testing.
    :param max_age: An optional maximum age of the ``iat`` claim.
    :param claims_options: Extra joserfc claims options.
    :return: The validated logout token claims.
    :raises joserfc.errors.JoseError: If the token is invalid.
    """
    if key is None:
        key = jwks
    if key is None:
        raise ValueError("A verification key is required")

    if client_id is not None:
        if audience is not None and audience != client_id:
            raise ValueError("'audience' and 'client_id' must match")
        audience = client_id

    key = _import_verification_key(key)
    algorithms = _get_verification_algorithms(key, algorithms)
    token = jwt.decode(token, key, algorithms=algorithms)

    options = {
        "iss": {"essential": True},
        "aud": {"essential": True},
        "iat": {"essential": True},
        "exp": {"essential": True},
        "jti": {"essential": True},
        "events": {"essential": True},
    }
    if issuer is not None:
        options["iss"]["value"] = issuer
    if audience is not None:
        if isinstance(audience, list):
            options["aud"]["values"] = audience
        else:
            options["aud"]["value"] = audience

    if claims_options:
        for name, option in claims_options.items():
            options.setdefault(name, {}).update(option)

    claims = LogoutTokenClaims(
        token.claims,
        token.header,
        options,
        params={"client_id": audience, "max_age": max_age},
    )
    claims.validate(now=now, leeway=leeway)
    return claims


parse_logout_token = validate_logout_token
