from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.http import JsonResponse

from ..base_client import BackchannelLogoutError
from ..base_client import BaseApp
from ..base_client import InvalidLogoutTokenError
from ..base_client import OAuth1Mixin
from ..base_client import OAuth2Mixin
from ..base_client import OAuthError
from ..base_client import OpenIDMixin
from ..base_client import call_destroy_session
from ..requests_client import OAuth1Session
from ..requests_client import OAuth2Session


class DjangoAppMixin:
    def save_authorize_data(self, request, **kwargs):
        state = kwargs.pop("state", None)
        if state:
            self.framework.set_state_data(request.session, state, kwargs)
        else:
            raise RuntimeError("Missing state value")

    def authorize_redirect(self, request, redirect_uri=None, **kwargs):
        """Create a HTTP Redirect for Authorization Endpoint.

        :param request: HTTP request instance from Django view.
        :param redirect_uri: Callback or redirect URI for authorization.
        :param kwargs: Extra parameters to include.
        :return: A HTTP redirect response.
        """
        rv = self.create_authorization_url(redirect_uri, **kwargs)
        self.save_authorize_data(request, redirect_uri=redirect_uri, **rv)
        return HttpResponseRedirect(rv["url"])


class DjangoOAuth1App(DjangoAppMixin, OAuth1Mixin, BaseApp):
    client_cls = OAuth1Session

    def authorize_access_token(self, request, **kwargs):
        """Fetch access token in one step.

        :param request: HTTP request instance from Django view.
        :return: A token dict.
        """
        params = request.GET.dict()
        state = params.get("oauth_token")
        if not state:
            raise OAuthError(description='Missing "oauth_token" parameter')

        data = self.framework.get_state_data(request.session, state)
        if not data:
            raise OAuthError(description='Missing "request_token" in temporary data')

        params["request_token"] = data["request_token"]
        params.update(kwargs)
        self.framework.clear_state_data(request.session, state)
        return self.fetch_access_token(**params)


class DjangoOAuth2App(DjangoAppMixin, OAuth2Mixin, OpenIDMixin, BaseApp):
    client_cls = OAuth2Session

    def backchannel_logout(
        self,
        request=None,
        logout_token=None,
        *,
        destroy_session=None,
        logout=None,
        **kwargs,
    ):
        """Handle an OpenID Connect back-channel logout request.

        :param request: HTTP request instance from the Django view.
        :param logout_token: The logout token. Read from the POST body when it
            is omitted.
        :return: An HTTP response with status 200 on success, 400 for an
            invalid token, or 500 when the session cannot be destroyed.
        """
        if request is not None and not hasattr(request, "POST"):
            logout_token, request = request, None
        if logout_token is not None and hasattr(logout_token, "POST"):
            request = logout_token
            logout_token = None
        if logout_token is None and request is not None:
            logout_token = request.POST.get("logout_token")

        try:
            claims = self.parse_logout_token(logout_token, consume_jti=False)
            if not self.validate_jti(claims, claims["jti"]):
                raise InvalidLogoutTokenError(
                    "jti", "The back-channel logout token was already used."
                )
        except InvalidLogoutTokenError as error:
            return JsonResponse(
                {"error": error.error, "error_description": error.description},
                status=400,
            )

        hook = destroy_session or logout or self.destroy_session
        try:
            call_destroy_session(hook, claims)
        except Exception:
            self.release_jti(claims["jti"])
            error = BackchannelLogoutError()
            return JsonResponse(
                {
                    "error": error.error,
                    "error_description": "The local session could not be destroyed.",
                },
                status=error.status_code,
            )
        return HttpResponse(status=200)

    handle_backchannel_logout = backchannel_logout

    def logout_redirect(
        self, request, post_logout_redirect_uri=None, id_token_hint=None, **kwargs
    ):
        """Create a HTTP Redirect for End Session Endpoint (RP-Initiated Logout).

        :param request: HTTP request instance from Django view.
        :param post_logout_redirect_uri: URI to redirect after logout.
        :param id_token_hint: ID Token previously issued to the RP.
        :param kwargs: Extra parameters (state, client_id, logout_hint, ui_locales).
        :return: A HTTP redirect response.
        """
        result = self.create_logout_url(
            post_logout_redirect_uri=post_logout_redirect_uri,
            id_token_hint=id_token_hint,
            **kwargs,
        )
        if result.get("state"):
            self.framework.set_state_data(
                request.session,
                result["state"],
                {
                    "post_logout_redirect_uri": post_logout_redirect_uri,
                },
            )
        return HttpResponseRedirect(result["url"])

    def validate_logout_response(self, request):
        """Validate the state parameter from the logout callback.

        :param request: HTTP request instance from Django view.
        :return: The state data dict.
        :raises OAuthError: If state is missing or invalid.
        """
        state = request.GET.get("state")
        if not state:
            raise OAuthError(description='Missing "state" parameter')

        state_data = self.framework.get_state_data(request.session, state)
        if not state_data:
            raise OAuthError(description='Invalid "state" parameter')

        self.framework.clear_state_data(request.session, state)
        return state_data

    def authorize_access_token(self, request, **kwargs):
        """Fetch access token in one step.

        :param request: HTTP request instance from Django view.
        :return: A token dict.
        """
        data = request.GET if request.method == "GET" else request.POST
        error = data.get("error")
        if error:
            description = data.get("error_description")
            uri = data.get("error_uri")
            raise OAuthError(error=error, description=description, uri=uri)

        params = {"code": data.get("code"), "state": data.get("state")}

        state_data = self.framework.get_state_data(request.session, params.get("state"))
        self.framework.clear_state_data(request.session, params.get("state"))
        params = self._format_state_params(state_data, params)

        claims_options = kwargs.pop("claims_options", None)
        claims_cls = kwargs.pop("claims_cls", None)
        leeway = kwargs.pop("leeway", 120)
        token = self.fetch_access_token(**params, **kwargs)

        if "id_token" in token and "nonce" in state_data:
            userinfo = self.parse_id_token(
                token,
                nonce=state_data["nonce"],
                claims_options=claims_options,
                claims_cls=claims_cls,
                leeway=leeway,
            )
            token["userinfo"] = userinfo
        return token
