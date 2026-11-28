"""Back-channel logout receiver for OpenID Connect Relying Parties.

https://openid.net/specs/openid-connect-backchannel-1_0.html
"""

import time

from joserfc.errors import InvalidClaimError
from joserfc.errors import JoseError

from .logout_token import validate_logout_token


class BackchannelLogoutReceiver:
    """Receive and validate logout tokens, and destroy the matching session.

    The receiver does not own any session storage. Subclasses must implement
    :meth:`destroy_session` to delete the local sessions matching ``sub`` and
    ``sid``. The receiver calls it only after the logout token is validated
    and its ``jti`` is consumed.

    The default replay store is kept in memory. In a multi-process deployment,
    pass a shared ``replay_store`` implementing ``__contains__`` and
    ``__setitem__``, or override :meth:`is_jti_used` and :meth:`record_jti`.
    """

    #: HTTP status returned by :meth:`handle` when the token is invalid.
    INVALID_TOKEN_STATUS = 400
    #: HTTP status returned by :meth:`handle` when the session cannot be
    #: destroyed. Unlike an invalid token, the OP may retry this request.
    LOGOUT_FAILED_STATUS = 500
    #: HTTP status returned on success.
    SUCCESS_STATUS = 200

    def __init__(
        self,
        issuer=None,
        audience=None,
        jwks=None,
        algorithms=None,
        leeway=120,
        max_age=None,
        replay_store=None,
    ):
        self.issuer = issuer
        self.audience = audience
        self.jwks = jwks
        self.algorithms = algorithms
        self.leeway = leeway
        self.max_age = max_age
        self._replay_store = replay_store if replay_store is not None else {}

    def get_issuer(self):
        return self.issuer

    def get_audience(self):
        return self.audience

    def get_jwks(self):
        return self.jwks

    def get_algorithms(self):
        return self.algorithms

    def validate_logout_token(self, token, *, consume_jti=True):
        """Validate ``token``, consume its ``jti``, and return its claims."""
        claims = validate_logout_token(
            token,
            self.get_jwks(),
            issuer=self.get_issuer(),
            audience=self.get_audience(),
            algorithms=self.get_algorithms(),
            leeway=self.leeway,
            max_age=self.max_age,
        )
        if consume_jti and not self.validate_jti(claims, claims["jti"]):
            raise InvalidClaimError("jti")
        return claims

    def validate_jti(self, claims, jti):
        """Return ``True`` if ``jti`` was not used, and record it.

        Override this method to use the application replay store.
        """
        if self.is_jti_used(jti):
            return False
        self.record_jti(jti, claims.get("exp"))
        return True

    def is_jti_used(self, jti):
        expires_at = self._replay_store.get(jti)
        if expires_at is None:
            return False
        if expires_at < int(time.time()):
            self._replay_store.pop(jti, None)
            return False
        return True

    def record_jti(self, jti, expires_at=None):
        if expires_at is None:
            expires_at = int(time.time()) + self.leeway
        self._replay_store[jti] = expires_at

    def release_jti(self, jti):
        """Forget a ``jti`` after a session destruction failure."""
        self._replay_store.pop(jti, None)

    def destroy_session(self, sub, sid):
        """Destroy the local sessions matching ``sub`` and ``sid``.

        Developers MUST implement this method. ``sub`` and ``sid`` may be
        ``None`` when the logout token does not contain the claim.
        :raises Exception: If the session could not be destroyed.
        """
        raise NotImplementedError()

    def logout(self, claims):
        """Destroy the session of the validated logout token."""
        self.destroy_session(claims.get("sub"), claims.get("sid"))

    def handle(self, token):
        """Validate ``token`` and destroy the matching session.

        :return: ``200`` on success, ``400`` for an invalid token, and ``500``
            when the session destruction fails.
        """
        try:
            claims = self.validate_logout_token(token)
        except (JoseError, ValueError):
            return self.INVALID_TOKEN_STATUS

        try:
            self.logout(claims)
        except Exception:
            self.release_jti(claims["jti"])
            return self.LOGOUT_FAILED_STATUS
        return self.SUCCESS_STATUS


BackchannelLogoutHandler = BackchannelLogoutReceiver
