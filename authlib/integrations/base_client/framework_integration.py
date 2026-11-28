import json
import time


class FrameworkIntegration:
    expires_in = 3600

    def __init__(self, name, cache=None):
        self.name = name
        self.cache = cache

    def _get_cache_data(self, key):
        value = self.cache.get(key)
        if not value:
            return None
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return None

    def _clear_session_state(self, session):
        now = time.time()
        prefix = f"_state_{self.name}"
        for key in dict(session):
            if key.startswith(prefix):
                value = session[key]
                exp = value.get("exp")
                if not exp or exp < now:
                    session.pop(key)

    def get_state_data(self, session, state):
        key = f"_state_{self.name}_{state}"
        session_data = session.get(key)
        if not session_data:
            return None
        if self.cache:
            cached_value = self._get_cache_data(key)
        else:
            cached_value = session_data
        if cached_value:
            return cached_value.get("data")
        return None

    def set_state_data(self, session, state, data):
        key = f"_state_{self.name}_{state}"
        now = time.time()
        if self.cache:
            self.cache.set(key, json.dumps({"data": data}), self.expires_in)
            session[key] = {"exp": now + self.expires_in}
        else:
            session[key] = {"data": data, "exp": now + self.expires_in}

    def clear_state_data(self, session, state):
        key = f"_state_{self.name}_{state}"
        if self.cache and key in session:
            self.cache.delete(key)

        session.pop(key, None)
        self._clear_session_state(session)

    def _get_jti_records(self):
        records = getattr(self, "_jti_records", None)
        if records is None:
            records = {}
            self._jti_records = records
        return records

    def _get_jti_key(self, jti):
        return f"_jti_{self.name}_{jti}"

    def is_jti_used(self, jti):
        """Tell whether a logout token ``jti`` was already consumed.

        With a cache, the record is shared by all the workers. Without one,
        the record is kept in memory by this integration instance.
        """
        key = self._get_jti_key(jti)
        if self.cache:
            return bool(self.cache.get(key))

        records = self._get_jti_records()
        expires_at = records.get(jti)
        if expires_at is None:
            return False
        if expires_at < time.time():
            records.pop(jti, None)
            return False
        return True

    def record_jti(self, jti, expires_at=None):
        """Record a logout token ``jti`` as consumed."""
        now = time.time()
        if expires_at is None:
            expires_at = now + self.expires_in
        timeout = max(1, int(expires_at - now))

        key = self._get_jti_key(jti)
        if self.cache:
            self.cache.set(key, 1, timeout)
        else:
            self._get_jti_records()[jti] = expires_at

    def release_jti(self, jti):
        """Forget a recorded logout token ``jti``.

        This is used when the local session could not be destroyed, so that
        the OpenID Provider can retry the logout request.
        """
        key = self._get_jti_key(jti)
        if self.cache:
            self.cache.delete(key)
        else:
            self._get_jti_records().pop(jti, None)

    def destroy_session(self, sub, sid):
        """Destroy the local sessions identified by ``sub`` and ``sid``.

        Override this method in the framework integration, or in the remote
        application. It is called only for a valid and not-yet-used logout
        token. Raise an exception when the sessions could not be destroyed.
        """
        return True

    def update_token(self, token, refresh_token=None, access_token=None):
        raise NotImplementedError()

    @staticmethod
    def load_config(oauth, name, params):
        raise NotImplementedError()
