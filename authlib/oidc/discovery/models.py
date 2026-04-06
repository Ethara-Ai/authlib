from authlib.oauth2.rfc8414 import AuthorizationServerMetadata
from authlib.oauth2.rfc8414.models import validate_array_value
from authlib.oauth2.rfc8414.models import validate_boolean_value


class OpenIDProviderMetadata(AuthorizationServerMetadata):
    """OpenID Provider Metadata for OpenID Connect Discovery.

    The :meth:`validate` method can compose extension classes via the
    ``metadata_classes`` parameter. For example, to validate RP-Initiated
    Logout metadata::

        from authlib.oidc import discovery, rpinitiated

        metadata = discovery.OpenIDProviderMetadata(data)
        metadata.validate(metadata_classes=[rpinitiated.OpenIDProviderMetadata])
    """

    REGISTRY_KEYS = [
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
        "registration_endpoint",
        "scopes_supported",
        "response_types_supported",
        "response_modes_supported",
        "grant_types_supported",
        "token_endpoint_auth_methods_supported",
        "service_documentation",
        "ui_locales_supported",
        "op_policy_uri",
        "op_tos_uri",
        # added by OpenID
        "token_endpoint_auth_signing_alg_values_supported",
        "acr_values_supported",
        "subject_types_supported",
        "id_token_signing_alg_values_supported",
        "id_token_encryption_alg_values_supported",
        "id_token_encryption_enc_values_supported",
        "userinfo_signing_alg_values_supported",
        "userinfo_encryption_alg_values_supported",
        "userinfo_encryption_enc_values_supported",
        "request_object_signing_alg_values_supported",
        "request_object_encryption_alg_values_supported",
        "request_object_encryption_enc_values_supported",
        "display_values_supported",
        "claim_types_supported",
        "claims_supported",
        "claims_locales_supported",
        "claims_parameter_supported",
        "request_parameter_supported",
        "request_uri_parameter_supported",
        "require_request_uri_registration",
        # not defined by OpenID
        # 'revocation_endpoint',
        # 'revocation_endpoint_auth_methods_supported',
        # 'revocation_endpoint_auth_signing_alg_values_supported',
        # 'introspection_endpoint',
        # 'introspection_endpoint_auth_methods_supported',
        # 'introspection_endpoint_auth_signing_alg_values_supported',
        # 'code_challenge_methods_supported',
    ]

    def validate_jwks_uri(self):
        # REQUIRED in OpenID Connect
        jwks_uri = self.get("jwks_uri")
        if jwks_uri is None:
            raise ValueError('"jwks_uri" is required')
        return super().validate_jwks_uri()

    def validate_acr_values_supported(self):
        """OPTIONAL. JSON array containing a list of the Authentication
        Context Class References that this OP supports.
        """
        pass

    def validate_subject_types_supported(self):
        """REQUIRED. JSON array containing a list of the Subject Identifier
        types that this OP supports. Valid types include pairwise and public.
        """
        pass

    def validate_id_token_signing_alg_values_supported(self):
        """REQUIRED. JSON array containing a list of the JWS signing
        algorithms (alg values) supported by the OP for the ID Token to
        encode the Claims in a JWT [JWT]. The algorithm RS256 MUST be
        included. The value none MAY be supported, but MUST NOT be used
        unless the Response Type used returns no ID Token from the
        Authorization Endpoint (such as when using the Authorization
        Code Flow).
        """
        pass

    def validate_id_token_encryption_alg_values_supported(self):
        """OPTIONAL. JSON array containing a list of the JWE encryption
        algorithms (alg values) supported by the OP for the ID Token to
        encode the Claims in a JWT.
        """
        pass

    def validate_id_token_encryption_enc_values_supported(self):
        """OPTIONAL. JSON array containing a list of the JWE encryption
        algorithms (enc values) supported by the OP for the ID Token to
        encode the Claims in a JWT.
        """
        pass

    def validate_userinfo_signing_alg_values_supported(self):
        """OPTIONAL. JSON array containing a list of the JWS signing
        algorithms (alg values) [JWA] supported by the UserInfo Endpoint
        to encode the Claims in a JWT. The value none MAY be included.
        """
        pass

    def validate_userinfo_encryption_alg_values_supported(self):
        """OPTIONAL. JSON array containing a list of the JWE encryption
        algorithms (alg values) [JWA] supported by the UserInfo Endpoint
        to encode the Claims in a JWT.
        """
        pass

    def validate_userinfo_encryption_enc_values_supported(self):
        """OPTIONAL. JSON array containing a list of the JWE encryption
        algorithms (enc values) [JWA] supported by the UserInfo Endpoint
        to encode the Claims in a JWT.
        """
        pass

    def validate_request_object_signing_alg_values_supported(self):
        """OPTIONAL. JSON array containing a list of the JWS signing
        algorithms (alg values) supported by the OP for Request Objects,
        which are described in Section 6.1 of OpenID Connect Core 1.0.
        These algorithms are used both when the Request Object is passed
        by value (using the request parameter) and when it is passed by
        reference (using the request_uri parameter). Servers SHOULD support
        none and RS256.
        """
        pass

    def validate_request_object_encryption_alg_values_supported(self):
        """OPTIONAL. JSON array containing a list of the JWE encryption
        algorithms (alg values) supported by the OP for Request Objects.
        These algorithms are used both when the Request Object is passed
        by value and when it is passed by reference.
        """
        pass

    def validate_request_object_encryption_enc_values_supported(self):
        """OPTIONAL. JSON array containing a list of the JWE encryption
        algorithms (enc values) supported by the OP for Request Objects.
        These algorithms are used both when the Request Object is passed
        by value and when it is passed by reference.
        """
        pass

    def validate_display_values_supported(self):
        """OPTIONAL. JSON array containing a list of the display parameter
        values that the OpenID Provider supports. These values are described
        in Section 3.1.2.1 of OpenID Connect Core 1.0.
        """
        pass

    def validate_claim_types_supported(self):
        """OPTIONAL. JSON array containing a list of the Claim Types that
        the OpenID Provider supports. These Claim Types are described in
        Section 5.6 of OpenID Connect Core 1.0. Values defined by this
        specification are normal, aggregated, and distributed. If omitted,
        the implementation supports only normal Claims.
        """
        pass

    def validate_claims_supported(self):
        """RECOMMENDED. JSON array containing a list of the Claim Names
        of the Claims that the OpenID Provider MAY be able to supply values
        for. Note that for privacy or other reasons, this might not be an
        exhaustive list.
        """
        pass

    def validate_claims_locales_supported(self):
        """OPTIONAL. Languages and scripts supported for values in Claims
        being returned, represented as a JSON array of BCP47 [RFC5646]
        language tag values. Not all languages and scripts are necessarily
        supported for all Claim values.
        """
        pass

    def validate_claims_parameter_supported(self):
        """OPTIONAL. Boolean value specifying whether the OP supports use of
        the claims parameter, with true indicating support. If omitted, the
        default value is false.
        """
        pass

    def validate_request_parameter_supported(self):
        """OPTIONAL. Boolean value specifying whether the OP supports use of
        the request parameter, with true indicating support. If omitted, the
        default value is false.
        """
        pass

    def validate_request_uri_parameter_supported(self):
        """OPTIONAL. Boolean value specifying whether the OP supports use of
        the request_uri parameter, with true indicating support. If omitted,
        the default value is true.
        """
        pass

    def validate_require_request_uri_registration(self):
        """OPTIONAL. Boolean value specifying whether the OP requires any
        request_uri values used to be pre-registered using the request_uris
        registration parameter. Pre-registration is REQUIRED when the value
        is true. If omitted, the default value is false.
        """
        pass

    @property
    def claim_types_supported(self):
        # If omitted, the implementation supports only normal Claims
        pass

    @property
    def claims_parameter_supported(self):
        # If omitted, the default value is false.
        pass

    @property
    def request_parameter_supported(self):
        # If omitted, the default value is false.
        pass

    @property
    def request_uri_parameter_supported(self):
        # If omitted, the default value is true.
        pass

    @property
    def require_request_uri_registration(self):
        # If omitted, the default value is false.
        pass
