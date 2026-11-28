import inspect


def call_destroy_session(func, claims):
    """Call a session destruction hook with the signatures applications use.

    ``func`` may accept ``(sub, sid)``, ``(claims)``, or ``(**claims)``.
    A return value of ``False`` means the sessions were not destroyed.
    """
    sub = claims.get("sub")
    sid = claims.get("sid")

    try:
        parameters = inspect.signature(func).parameters
    except (TypeError, ValueError):
        parameters = {}

    names = set(parameters)
    if "claims" in names and "sub" not in names and "sid" not in names:
        result = func(claims)
    elif "sub" in names or "sid" in names:
        result = func(sub=sub, sid=sid)
    elif any(p.kind is p.VAR_KEYWORD for p in parameters.values()):
        result = func(sub=sub, sid=sid)
    else:
        result = func(sub, sid)

    if result is False:
        raise RuntimeError("The local session could not be destroyed.")
    return result
