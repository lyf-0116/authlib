import logging
import time

from joserfc import jwt
from joserfc.errors import JoseError

from authlib._joserfc_helpers import import_any_key
from authlib.deprecate import deprecate

from ..rfc6749 import TokenMixin
from ..rfc9068.token_validator import BaseJWTBearerTokenValidator

logger = logging.getLogger(__name__)


class JWTBearerToken(TokenMixin, dict):
    def check_client(self, client):
        return self["client_id"] == client.get_client_id()

    def get_scope(self):
        return self.get("scope")

    def get_expires_in(self):
        return self["exp"] - self["iat"]

    def is_expired(self):
        return self["exp"] < time.time()

    def is_revoked(self):
        return False


class JWTBearerTokenValidator(BaseJWTBearerTokenValidator):
    """Validate JWT access tokens, such as those of ``JWTBearerTokenGenerator``.

    :param public_key: the key that verifies the token signature.
    :param issuer: the expected ``iss`` value.
    :param audience: the identifier of this resource server, as a string. When
        it is set, the ``aud`` claim must contain it. When it is not set, tokens
        with an ``aud`` claim are rejected.
    :param realm: the realm of the ``WWW-Authenticate`` header.
    :param leeway: the clock skew tolerance, in seconds.

    .. deprecated:: 1.10
        Use :class:`authlib.oauth2.rfc9068.JWTBearerTokenValidator`, which
        follows :rfc:`9068`.
    """

    TOKEN_TYPE = "bearer"
    token_cls = JWTBearerToken

    def __init__(
        self,
        public_key,
        issuer=None,
        realm=None,
        leeway=60,
        audience=None,
        **extra_attributes,
    ):
        deprecate(
            "'authlib.oauth2.rfc7523.JWTBearerTokenValidator' is deprecated, "
            "use 'authlib.oauth2.rfc9068.JWTBearerTokenValidator' instead.",
            version="2.0.0",
        )
        super().__init__(
            issuer=issuer,
            resource_server=audience,
            realm=realm,
            leeway=leeway,
            require_audience=False,
            token_type_policy="warn",
            jti_policy="warn",
            reject_unexpected_audience=True,
            **extra_attributes,
        )
        self.public_key = import_any_key(public_key)
        self.claims_options = self.get_claims_options()

    def get_jwks(self):
        return self.public_key

    def get_claims_options(self):
        claims_options = super().get_claims_options()
        claims_options["grant_type"] = {"essential": True}
        return claims_options

    def authenticate_token(self, token_string: str):
        try:
            token = jwt.decode(token_string, self.public_key)
        except JoseError as error:
            logger.debug("Authenticate token failed. %r", error)
            return None

        # Existing issuers do not necessarily declare the 'at+jwt' typ
        # header or a 'jti' claim yet, so those are only warned about for
        # now. They will be enforced in version 2.0.0.
        self.check_token_type(token.header)
        self.check_jti(token.claims)

        claims_requests = jwt.JWTClaimsRegistry(
            leeway=self.leeway, **self.claims_options
        )
        try:
            claims_requests.validate(token.claims)
        except JoseError as error:
            logger.debug("Authenticate token failed. %r", error)
            return None

        # Per RFC 7519 §4.1.3, if the principal processing the claim does not
        # identify itself with a value in the "aud" claim when this claim is
        # present, then the JWT MUST be rejected.
        if self.has_unexpected_audience(token.claims, self.claims_options):
            logger.debug("Authenticate token failed. Unexpected 'aud' claim.")
            return None

        return self.token_cls(token.claims)
