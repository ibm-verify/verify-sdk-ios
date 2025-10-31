//
// Copyright contributors to the IBM Verify Authentication SDK for iOS project
//

import Core

/// The metadata that describes an OpenID Connect  Provider configuration.
public struct OIDCMetadataInfo: Decodable {
    /// The Issuer Identifier of the OpenID Connect Provider. This value is the same as the `iss` claim value in the ID tokens issued by this provider.
    public let issuer: String
    
    /// The URL of the OpenID Connect Provider's OAuth 2.0 Authorization Endpoint.
    public let authorizationEndpoint: String
    
    /// The URL of the OpenID Connect Provider's OAuth 2.0 Token Endpoint.
    public let tokenEndpoint: String
    
    /// The URL of the OpenID Connect Provider's UserInfo Endpoint.
    public let userinfoEndpoint: String
    
    /// The URL of the OpenID Connect Provider's JSON Web Key Set document. This document contains signing keys that clients use to validate the signatures from the provider.
    public let jwksUri: String
    
    /// The URL of the OpenID Connect Provider's Dynamic Client Registration Endpoint
    public let registrationEndpoint: String
   
    /// An array containing a list of OAuth 2.0 response types supported by this provider.
    public  let responseTypesSupported: [String]
    
    /// An array containing a list of OAuth 2.0 response modes supported by this provider.
    public let responseModesSupported: [String]
    
    /// An array containing a list of OAuth 2.0 grant types supported by this provider.
    ///
    /// If omitted, the default valuea are `authorization_code` and `implicit`.
    /// - Remark: Implicit grant type is not supported for mobile.
    public var grantTypesSupported: [String] = ["authorization_code", "implicit"]
   
    /// An array containing a list of Subject Identifier types supported by this provider.
    public let subjectTypesSupported: [String]
    
    /// An array containing a list of the JWS signing algorithms (alg values) supported by this provider for the ID Token to encode the Claims in a JWT.
    public let idTokenSigningAlgValuesSupported: [String]
   
    /// An array containing a list of the JWE encryption algorithms (alg values) supported by this provider for the ID Token to encode the Claims in a JWT.
    public var idTokenEncryptionAlgValuesSupported: [String] = ["none"]
    
    /// An array containing a list of the JWE encryption algorithms (enc values) supported by this provider for the ID Token to encode the Claims in a JWT.
    public var idTokenEncryptionEncValuesSupported: [String] = ["none"]
    
    /// An array containing a list of the JWS signing algorithms (alg values) JWA supported by the UserInfo Endpoint to encode the Claims in a JWT.
    public var userinfoSigningAlgValuesSupported: [String] = ["none"]
                                                           
    /// An array containing a list of the JWE encryption algorithms (alg values) JWA supported by the UserInfo Endpoint to encode the Claims in a JWT.
    public var userinfoEncryptionAlgValuesSupported: [String] = ["none"]
    
    /// An array containing a list of the JWE encryption algorithms (enc values) JWA supported by the UserInfo Endpoint to encode the Claims in a JWT.
    public var userinfoEncryptionEncValuesSupported: [String] = ["none"]
    
    /// An array containing a list of the JWS signing algorithms (alg values) supported by the OpenID Connect Provider for Request Objects.
    public var requestObjectSigningAlgValuesSupported: [String] = ["none"]
    
    /// An array containing a list of the JWE encryption algorithms (alg values) supported by the OpenID Connect Provider for Request Objects.
    public var requestObjectEncryptionAlgValuesSupported: [String] = ["none"]
    
    /// An array containing a list of the JWE encryption algorithms (enc values) supported by the OpenID Connect Provider for Request Objects.
    public var requestObjectEncryptionEncValuesSupported: [String] = ["none"]
    
    /// An array containing a list of Client Authentication methods supported by this Token Endpoint. The options are `client_secret_post`, `client_secret_basic`, `client_secret_jwt`, and `private_key_jwt`.
    ///
    /// If omitted, the default value is `client_secret_basic`.
    public var tokenEndpointAuthMethodsSupported: [String] = ["client_secret_basic"]
    
    /// An array containing a list of the JWS signing algorithms (alg values) supported by the Token Endpoint for the signature on the JWT used to authenticate the Client at the Token Endpoint for the `private_key_jwt` and `client_secret_jwt` authentication methods.
    public var tokenEndpointAuthSigningAlgValuesSupported: [String]?
    
    /// An array containing a list of the display parameter values that the OpenID Provider supports.
    public var displayValuesSupported: [String]?
    
    /// An array containing a list of the Claim Types that the OpenID Provider supports.
    ///
    /// If omitted, the default value is `normal`.
    public var claimTypesSupported: [String] = ["normal"]
    
    /// An array containing a list of the Claim Names of the Claims that the OpenID Provider **may** be able to supply values for.
    public var claimsSupported: [String] = []
    
    /// A URL of a page containing human-readable information that developers might want or need to know when using the OpenID Provider.
    public let serviceDocumentation: String?
    
    /// An array of languages and scripts supported for values in Claims being returned.
    public let claimsLocalesSupported: [String]?
    
    /// An array of languages and scripts supported for the user interface.
    public let uiLocalesSupported: [String]?
    
    /// A boolean value specifying whether the OpenID Provider supports use of the claims parameter, with `true` indicating support.
    ///
    /// If omitted, the default value is `false`.
    @Default.False public var claimsParameterSupported: Bool
    
    /// A boolean value specifying whether the OpenID Provider supports use of the request parameter, with true indicating support.
    ///
    /// If omitted, the default value is `false`.
    @Default.False public var requestParameterSupported: Bool
   
    /// A boolean value specifying whether the OpenID Provider supports use of the `request_uri` parameter, with `true` indicating support.
    ///
    /// If omitted, the default value is `true`.
    @Default.True public var requestUriParameterSupported: Bool
    
    /// A boolean value specifying whether the OpenID Provider requires any `request_uri` values used to be pre-registered using the `request_uris` registration parameter. Pre-registration is **required** when the value is `true`.
    ///
    /// If omitted, the default value is `false`.
    @Default.False public var requireRequestUriRegistration: Bool
   
    /// A  URL that the OpenID Provider provides to the person registering the Client to read about the OP's requirements on how the Relying Party can use the data provided by the OpenID Provider.
    public let opPolicyUri: String?
    
    /// A URL that the OpenID Provider provides to the person registering the Client to read about OpenID Provider's terms of service.
    public let opToSUri: String?
}
