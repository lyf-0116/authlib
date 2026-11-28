from authlib.common.errors import AuthlibBaseError


class OAuthError(AuthlibBaseError):
    error = "oauth_error"


class MissingRequestTokenError(OAuthError):
    error = "missing_request_token"


class MissingTokenError(OAuthError):
    error = "missing_token"


class TokenExpiredError(OAuthError):
    error = "token_expired"


class InvalidTokenError(OAuthError):
    error = "token_invalid"


class InvalidLogoutTokenError(InvalidTokenError):
    """Raised when a back-channel logout token cannot be decoded or validated.

    The original joserfc error is available as ``__cause__``.
    """

    error = "invalid_logout_token"


class UnsupportedTokenTypeError(OAuthError):
    error = "unsupported_token_type"


class BackchannelLogoutError(OAuthError):
    """Raised when a validated logout token cannot destroy the local session."""

    error = "backchannel_logout_failed"
    status_code = 500


class MismatchingStateError(OAuthError):
    error = "mismatching_state"
    description = "CSRF Warning! State not equal in request and response."


class MismatchingIssuerError(OAuthError):
    error = "mismatching_issuer"
