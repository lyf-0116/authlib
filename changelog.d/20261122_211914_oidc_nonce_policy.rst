Added
~~~~~

- The OpenID Connect web clients accept a ``nonce_policy`` when registering a
  client or calling ``parse_id_token``. A missing expected nonce now emits a
  ``MissingNonceWarning`` by default instead of silently disabling replay
  protection; ``"required"`` rejects such ID tokens with
  ``MissingNonceError`` and ``"ignored"`` keeps the previous silent behavior.
  The expected nonce remains fully controlled by the application, and token
  claims can never enable or disable its validation.
