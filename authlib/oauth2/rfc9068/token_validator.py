"""authlib.oauth2.rfc9068.token_validator.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Implementation of Validating JWT Access Tokens per :rfc:`9068#section-4`.
"""

from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.errors import MissingClaimError

from authlib._joserfc_helpers import import_any_key
from authlib.deprecate import deprecate
from authlib.oauth2.claims import ClaimsOption
from authlib.oauth2.rfc6750.errors import InsufficientScopeError
from authlib.oauth2.rfc6750.errors import InvalidTokenError
from authlib.oauth2.rfc6750.validator import BearerTokenValidator

from .claims import _ACCESS_TOKEN_TYPES
from .claims import JWTAccessTokenClaims


class BaseJWTBearerTokenValidator(BearerTokenValidator):
    """The shared core of the JWT access token validators.

    :param issuer: The issuer from which tokens are accepted. When it is
        set, the ``iss`` claim must exactly match it. When it is not set,
        the ``iss`` claim is not checked.
    :param resource_server: An identifier for the current resource server.
        When it is set, the ``aud`` claim must contain it.
    :param require_audience: When ``True`` (the default), the ``aud`` claim
        must be present, even if no ``resource_server`` is configured.
    :param token_type_policy: How the ``typ`` header is checked against
        ``at+jwt`` and ``application/at+jwt``: ``"enforce"`` rejects tokens
        of another type, ``"warn"`` only emits a deprecation warning, and
        ``"ignore"`` skips the check.
    :param jti_policy: How the ``jti`` claim is checked: ``"enforce"``
        requires the claim, ``"warn"`` only emits a deprecation warning
        when it is missing, and ``"ignore"`` skips the check.
    :param reject_unexpected_audience: When no audience is configured
        (``resource_server`` is ``None`` and ``require_audience`` is
        ``False``), reject tokens carrying an ``aud`` claim.
    :param leeway: The clock skew tolerance, in seconds.
    """

    _POLICIES = ("enforce", "warn", "ignore")

    def __init__(
        self,
        issuer=None,
        resource_server=None,
        *args,
        require_audience=True,
        token_type_policy="enforce",
        jti_policy="enforce",
        reject_unexpected_audience=False,
        leeway=0,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        for name, policy in (
            ("token_type_policy", token_type_policy),
            ("jti_policy", jti_policy),
        ):
            if policy not in self._POLICIES:
                raise ValueError(
                    f"Invalid {name}: {policy!r}. "
                    f"Expected one of {', '.join(self._POLICIES)}."
                )
        self.issuer = issuer
        self.resource_server = resource_server
        self.require_audience = require_audience
        self.token_type_policy = token_type_policy
        self.jti_policy = jti_policy
        self.reject_unexpected_audience = reject_unexpected_audience
        self.leeway = leeway

    def get_jwks(self):
        """Return the JWKs that will be used to check the JWT access token signature.
        Developers MUST re-implement this method. Typically the JWKs are statically
        stored in the resource server configuration, or dynamically downloaded and
        cached using :ref:`specs/rfc8414`::

            def get_jwks(self):
                if "jwks" in cache:
                    return cache.get("jwks")

                server_metadata = get_server_metadata(self.issuer)
                jwks_uri = server_metadata.get("jwks_uri")
                cache["jwks"] = requests.get(jwks_uri).json()
                return cache["jwks"]
        """
        raise NotImplementedError()

    def get_claims_options(self) -> dict[str, ClaimsOption]:
        """Build the claims options from the validator policies."""
        claims_options: dict[str, ClaimsOption] = {
            "exp": {"essential": True},
            "client_id": {"essential": True},
        }
        if self.issuer is not None:
            claims_options["iss"] = {"essential": True, "value": self.issuer}
        if self.resource_server is not None or self.require_audience:
            claims_options["aud"] = {
                "essential": True,
                "value": self.resource_server,
            }
        if self.jti_policy == "enforce":
            claims_options["jti"] = {"essential": True}
        return claims_options

    def check_token_type(self, header):
        """Apply the ``token_type_policy`` to the JWT header."""
        typ = header.get("typ")
        if typ and typ.lower() in _ACCESS_TOKEN_TYPES:
            return

        description = (
            "The access token 'typ' header must be 'at+jwt' or 'application/at+jwt'."
        )
        if self.token_type_policy == "warn":
            deprecate(
                f"{description} Tokens without it will be rejected.",
                version="2.0.0",
            )
        elif self.token_type_policy == "enforce":
            raise InvalidTokenError(
                description=description,
                realm=self.realm,
                extra_attributes=self.extra_attributes,
            )

    def check_jti(self, claims):
        """Apply the ``jti_policy`` to the JWT claims."""
        if self.jti_policy == "warn" and "jti" not in claims:
            deprecate(
                "The access token has no 'jti' claim. "
                "Tokens without it will be rejected.",
                version="2.0.0",
            )

    def has_unexpected_audience(self, claims, claims_options) -> bool:
        """Tell if the token carries an ``aud`` claim that no configured
        audience allows.
        """
        return (
            self.reject_unexpected_audience
            and "aud" not in claims_options
            and "aud" in claims
        )


class JWTBearerTokenValidator(BaseJWTBearerTokenValidator):
    """JWTBearerTokenValidator can protect your resource server endpoints.

    :param issuer: The issuer from which tokens will be accepted.
    :param resource_server: An identifier for the current resource server,
        which must appear in the JWT ``aud`` claim.

    Developers needs to implement the missing methods::

        class MyJWTBearerTokenValidator(JWTBearerTokenValidator):
            def get_jwks(self): ...


        require_oauth = ResourceProtector()
        require_oauth.register_token_validator(
            MyJWTBearerTokenValidator(
                issuer="https://authorization-server.example.org",
                resource_server="https://resource-server.example.org",
            )
        )

    You can then protect resources depending on the JWT `scope`, `groups`,
    `roles` or `entitlements` claims::

        @require_oauth(
            scope="profile",
            groups="admins",
            roles="student",
            entitlements="captain",
        )
        def resource_endpoint(): ...
    """

    def __init__(self, issuer, resource_server, *args, **kwargs):
        super().__init__(issuer, resource_server, *args, **kwargs)

    def validate_iss(self, claims, iss: "str") -> bool:
        # The issuer identifier for the authorization server (which is typically
        # obtained during discovery) MUST exactly match the value of the 'iss'
        # claim.
        return iss == self.issuer

    def get_claims_options(self) -> dict[str, ClaimsOption]:
        claims_options = super().get_claims_options()
        if self.issuer is not None:
            claims_options["iss"] = {
                "essential": True,
                "validate": self.validate_iss,
            }
        claims_options.update(
            {
                "sub": {"essential": True},
                "iat": {"essential": True},
                "auth_time": {"essential": False},
                "acr": {"essential": False},
                "amr": {"essential": False},
                "scope": {"essential": False},
                "groups": {"essential": False},
                "roles": {"essential": False},
                "entitlements": {"essential": False},
            }
        )
        return claims_options

    def authenticate_token(self, token_string):
        """"""
        # empty docstring avoids to display the irrelevant parent docstring

        key = import_any_key(self.get_jwks())

        # If the JWT access token is encrypted, decrypt it using the keys and algorithms
        # that the resource server specified during registration. If encryption was
        # negotiated with the authorization server at registration time and the incoming
        # JWT access token is not encrypted, the resource server SHOULD reject it.

        # The resource server MUST validate the signature of all incoming JWT access
        # tokens according to [RFC7515] using the algorithm specified in the JWT 'alg'
        # Header Parameter. The resource server MUST reject any JWT in which the value
        # of 'alg' is 'none'. The resource server MUST use the keys provided by the
        # authorization server.
        try:
            token = jwt.decode(token_string, key=key)
        except JoseError as exc:
            raise InvalidTokenError(
                realm=self.realm, extra_attributes=self.extra_attributes
            ) from exc

        return JWTAccessTokenClaims(
            token.claims,
            token.header,
            self.get_claims_options(),
            params={"token_type_policy": self.token_type_policy},
        )

    def validate_token(
        self,
        token: JWTAccessTokenClaims,
        scopes,
        request,
        groups=None,
        roles=None,
        entitlements=None,
    ):
        """"""
        # empty docstring avoids to display the irrelevant parent docstring

        # Per RFC 9068 §4, the resource server MUST verify that the typ
        # header value is at+jwt or application/at+jwt.
        self.check_token_type(token.header)

        try:
            token.validate(leeway=self.leeway)
        except MissingClaimError as exc:
            raise InvalidTokenError(
                description=exc.description,
                realm=self.realm,
                extra_attributes=self.extra_attributes,
            ) from exc
        except JoseError as exc:
            raise InvalidTokenError(
                realm=self.realm, extra_attributes=self.extra_attributes
            ) from exc

        # If an authorization request includes a scope parameter, the corresponding
        # issued JWT access token SHOULD include a 'scope' claim as defined in Section
        # 4.2 of [RFC8693]. All the individual scope strings in the 'scope' claim MUST
        # have meaning for the resources indicated in the 'aud' claim. See Section 5 for
        # more considerations about the relationship between scope strings and resources
        # indicated by the 'aud' claim.

        if self.scope_insufficient(token.get("scope", []), scopes):
            raise InsufficientScopeError()

        # Many authorization servers embed authorization attributes that go beyond the
        # delegated scenarios described by [RFC7519] in the access tokens they issue.
        # Typical examples include resource owner memberships in roles and groups that
        # are relevant to the resource being accessed, entitlements assigned to the
        # resource owner for the targeted resource that the authorization server knows
        # about, and so on. An authorization server wanting to include such attributes
        # in a JWT access token SHOULD use the 'groups', 'roles', and 'entitlements'
        # attributes of the 'User' resource schema defined by Section 4.1.2 of
        # [RFC7643]) as claim types.

        if self.scope_insufficient(token.get("groups"), groups):
            raise InvalidTokenError()

        if self.scope_insufficient(token.get("roles"), roles):
            raise InvalidTokenError()

        if self.scope_insufficient(token.get("entitlements"), entitlements):
            raise InvalidTokenError()
