//
// Copyright contributors to the IBM Verify FIDO2 SDK for iOS project
//

import Foundation

// MARK: Structures

/// Represents options provided when an authentication credential is created.
public struct PublicKeyCredentialCreationOptions: Codable {
    /// Represents relying party attributes provided when a credential is created.
    public var rp: PublicKeyCredentialRpEntity
    
    /// Represents user account information provided when a credential is created.
    public var user: PublicKeyCredentialUserEntity
    
    /// The challenge to be used for generating the newly created credential’s attestation object.
    public var challenge: String
    
    /// Represents additional options provided when a credential is created.
    public var pubKeyCredParams: [PublicKeyCredentialParameters]
    
    /// The time in milliseconds, that the caller is willing to wait for the call to complete.  Default is `30000` milliseconds.
    public var timeout: Int
    
    /// Represents credential parameters to be used for FIDO2 registration or authentication.
    public var excludeCredentials: [PublicKeyCredentialDescriptor]
    
    /// Represents configuration items related to the authenticator, which are specified by the WebAuthn relying party.
    public var authenticatorSelection: AuthenticatorSelectionCriteria
    
    /// Represents credential passing preferences, which are used by the WebAuthn relying party when the credential is created.
    public var attestation: AttestationConveyancePreference
    
    /// Represents additional parameters requesting additional processing by the client and authenticator.
    public var extensions: AuthenticatorExtensions?
    
    /// Creates a new `PublicKeyCredentialCreationOptions` instance.
    /// - Parameters:
    ///   - rp: Represents relying party attributes provided when a credential is created.
    ///   - user: Represents user account information provided when a credential is created.
    ///   - challenge: The challenge to be used for generating the newly created credential’s attestation object.
    ///   - pubKeyCredParams: Represents additional options provided when a credential is created.
    ///   - timeout: The time in milliseconds, that the caller is willing to wait for the call to complete.  Default is 30000 milliseconds.
    ///   - excludeCredentials: Represents credential parameters to be used for FIDO2 registration or authentication.
    ///   - authenticatorSelection: Represents configuration items related to the authenticator, which are specified by the WebAuthn relying party.
    ///   - attestation: Represents credential passing preferences, which are used by the WebAuthn relying party when the credential is created.
    public init(rp: PublicKeyCredentialRpEntity,
                user: PublicKeyCredentialUserEntity,
                challenge: String,
                timeout: Int = 30000,
                excludeCredentials: [PublicKeyCredentialDescriptor] = [PublicKeyCredentialDescriptor](),
                authenticatorSelection: AuthenticatorSelectionCriteria,
                attestation: AttestationConveyancePreference = .none,
                pubKeyCredParams: [PublicKeyCredentialParameters] = [PublicKeyCredentialParameters(alg: .es256)]) {
        self.rp = rp
        self.user = user
        self.challenge = challenge
        self.timeout = timeout
        self.excludeCredentials = excludeCredentials
        self.authenticatorSelection = authenticatorSelection
        self.attestation = attestation
        self.pubKeyCredParams = pubKeyCredParams
    }
    
    enum CodingKeys: String, CodingKey {
        case rp, user, challenge, timeout, excludeCredentials, authenticatorSelection, attestation, pubKeyCredParams
    }
}

/// The `PublicKeyCredentialRequestOptions` supplies get() with the data it needs to generate an assertion.
public struct PublicKeyCredentialRequestOptions: Codable {
    /// The challenge to be used for generating the newly created credential’s attestation object.
    public var challenge: String
    
    /// Represents relying party attributes provided when a credential is created.
    public var rpId: String?
    
    /// Contains a list of `PublicKeyCredentialDescriptor` objects representing public key credentials acceptable to the caller.
    public var allowCredentials: [PublicKeyCredentialDescriptor]?
    
    /// Describes the Relying Party's requirements regarding user verification for the `get()` operation.
    public var userVerification: UserVerificationRequirement
    
    /// The time in milliseconds, that the caller is willing to wait for the call to complete.  Default is `30000` milliseconds.
    public var timeout: Int
    
    /// Represents additional parameters requesting additional processing by the client and authenticator.
    public var extensions: AuthenticatorExtensions?
    
    /// Creates a new `PublicKeyCredentialRequestOptions` instance.
    public init(challenge: String, rpId: String = "", allowCredentials: [PublicKeyCredentialDescriptor] = [PublicKeyCredentialDescriptor](), userVerification: UserVerificationRequirement = .preferred, timeout: Int = 30000) {
        self.challenge = challenge
        self.rpId = rpId
        self.allowCredentials = allowCredentials
        self.userVerification = userVerification
        self.timeout = timeout
    }
    
    /// Creates a new instance by decoding from the given decoder
    /// - Parameter decoder: The decoder to read data from.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        challenge = try container.decode(String.self, forKey: .challenge)
        rpId = try container.decode(String.self, forKey: .rpId)
        allowCredentials = try container.decodeIfPresent([PublicKeyCredentialDescriptor].self, forKey: .allowCredentials)
        userVerification =  try container.decode(UserVerificationRequirement.self, forKey: .userVerification)
        timeout = try container.decode(Int.self, forKey: .timeout)
        extensions = try? container.decodeIfPresent(AuthenticatorExtensions.self, forKey: .extensions) ?? nil
    }
}

/// Represents relying party attributes provided when a credential is created.
public struct PublicKeyCredentialRpEntity: Codable {
    /// The unique identifier of a relying party.
    public let id: String?
    
    /// The relying party name.
    public let name: String
    
    /// A URL that refers to the relying party icon.
    public let icon: String?
    
    /// Creates a new `PublicKeyCredentialRpEntity` instance.
    /// - Parameters:
    ///   - id: The unique identifier of a relying party.
    ///   -  name: The relying party name.
    ///   - icon: A URL that refers to the relying party icon.
    public init(id: String? = nil, name: String, icon: String? = nil) {
        self.id = id ?? name
        self.name = name
        self.icon = icon
    }
}

/// Represents user account information provided when a credential is created.
public struct PublicKeyCredentialUserEntity: Codable {
    /// The unique identifier of a user.
    public let id: [UInt8]
    
    /// The display name of the user.
    public let displayName: String
    
    /// The name of the user.
    public let name: String
    
    /// A URL that refers to the users icon.
    public let icon: String?
    
    /// Creates a new `PublicKeyCredentialUserEntity` instance.
    /// - Parameters:
    ///   - id: The unique identifier of a user.
    ///   - displayName: The display name of the user.
    ///   - name: The name of the user.
    ///   - icon: A URL that refers to the users icon.
    public init(id: String, displayName: String, name: String, icon: String? = nil) {
        self.id = Array(id.utf8)
        self.displayName = displayName
        self.name = name
        self.icon = icon
    }
    
    enum CodingKeys: String, CodingKey {
        case id, displayName, name, icon
    }
    
    /// Creates a new instance by decoding from the given decoder
    /// - Parameter decoder: The decoder to read data from.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        // Convert the id from a String into an array of UInt8.
        let idValue = try container.decode(String.self, forKey: .id)
        id = Array(idValue.utf8)
        
        name = try container.decode(String.self, forKey: .name)
        displayName = try container.decode(String.self, forKey: .displayName)
        icon = try container.decodeIfPresent(String.self, forKey: .icon) ?? ""
    }
    
    /// Encodes this value into the given encoder.
    /// - Parameter encoder: The encoder to write data to.
   public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        // Convert the id from an array of UInt8 to String.
        let idValue = String(decoding: id, as: UTF8.self)
        try container.encode(idValue, forKey: .id)
        
        try container.encode(name, forKey: .name)
        try container.encode(displayName, forKey: .displayName)
        try container.encode(icon, forKey: .icon)
    }
}

/// Represents additional parameters when creating a new credential.
public struct PublicKeyCredentialParameters: Codable {
    /// The type of credential to be created.
    public let type: PublicKeyCredentialType
    
    /// The cryptographic signature algorithm with which the newly generated credential will use.
    public let alg: COSEAlgorithmIdentifier?
    
    /// Creates a new `PublicKeyCredentialParameters` instance.
    /// - Parameter alg: The supported algorithm.
    public init(alg: COSEAlgorithmIdentifier) {
        self.type = .publicKey
        self.alg = alg
    }
    
    enum CodingKeys: String, CodingKey {
        case alg
        case type
    }
    
    /// Creates a new instance by decoding from the given decoder
    /// - Parameter decoder: The decoder to read data from.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        type = .publicKey
        
        let value = try container.decode(Int.self, forKey: .alg)
        alg = COSEAlgorithmIdentifier.parse(from: value)
    }
}

/// Represents credential parameters to be used for FIDO2 registration or authentication.
public struct PublicKeyCredentialDescriptor: Codable {
    /// An enumeration for defining valid credential types.
    public let type: PublicKeyCredentialType
    
    /// The credential ID of the public key credential the caller is referring to.
    public let id: String // credential ID
    
    /// An array of transport type that can communicate with the client.
    public let transports: [AuthenticatorTransport]?
    
    /// Create a new `PublicKeyCredentialDescriptor` instance.
    /// - Parameters:
    ///   - id: The credential ID of the public key credential the caller is referring to.
    ///   - transports: An array of transport type that can communicate with the client.
    public init(id: String, transports: [AuthenticatorTransport]? = [.internal]) {
        self.id = id
        self.transports = transports
        self.type = .publicKey
    }
}

/// Authenticators respond to relying party requests by returning an object derived from this protocol.
public protocol AuthenticatorResponse: Codable {
    /// Contains the JSON of the client data, the hash of which is passed to the authenticator by the client in its call to either `WebAuthnAPIClient.create()` or `WebAuthnAPIClient.get()`
    var clientDataJSON: String {
        get
    }
}

/// The `AuthenticatorAttestationResponse` struct represents the authenticator's response to a client’s request for the creation of a new public key credential. It contains information about the new credential that can be used to identify it for later use, and metadata that can be used by the WebAuthn Relying Party to assess the characteristics of the credential during registration.
public struct AuthenticatorAttestationResponse: AuthenticatorResponse {
    /// Passed to the authenticator by the client in order to generate this credential.
    public var clientDataJSON: String
    
    /// Contains an attestation object, which is opaque to, and cryptographically protected against tampering by, the client. The attestation object contains both authenticator data and an attestation statement.
    public var attestationObject: [UInt8]
    
    /// Encodes this value into the given encoder.
    /// - Parameter encoder: The encoder to write data to.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        if let data = self.clientDataJSON.data(using: .utf8) {
            let base64ClientDataJSON = data.base64URLEncodedString()
            try container.encode(base64ClientDataJSON, forKey: .clientDataJSON)
        }
        
        let base64AttestationObject = Data(self.attestationObject).base64URLEncodedString()
        try container.encode(base64AttestationObject, forKey: .attestationObject)
    }
}

/// This structure contains cryptographic signatures produced by scoped credentials that provides proof of possession of a private key as well as evidence of user consent to a specific transaction.
public struct AuthenticatorAssertionResponse: AuthenticatorResponse {
    /// Passed to the authenticator by the client in order to generate this assertion.
    public var clientDataJSON: String
    
    /// Contains the authenticator data returned by the authenticator.
    public var authenticatorData: [UInt8]
    
    /// Contains the raw signature returned from the authenticator
    public var signature: [UInt8]
    
    /// Contains the user handle returned from the authenticator, or null if the authenticator did not return a user handle.
    public var userHandle: [UInt8]?
    
    /// Encodes this value into the given encoder.
    /// - Parameter encoder: The encoder to write data to.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        if let data = self.clientDataJSON.data(using: .utf8) {
            let base64ClientDataJSON = data.base64URLEncodedString()
            try container.encode(base64ClientDataJSON, forKey: .clientDataJSON)
        }
        
        let base64AssertionObject = Data(self.authenticatorData).base64URLEncodedString()
        try container.encode(base64AssertionObject, forKey: .authenticatorData)
        
        let base64SignatureObject = Data(self.signature).base64URLEncodedString()
        try container.encode(base64SignatureObject, forKey: .signature)
        
        if self.userHandle == nil {
            try container.encode ("", forKey: .userHandle)
        }
        else {
            let base64UserHandle = Data(self.userHandle!).base64URLEncodedString()
            try container.encode(base64UserHandle, forKey: .userHandle)
        }
    }
}

/// The `PublicKeyCredential` protocol contains the attributes that are returned to the caller when a new credential is created, or a new assertion is requested.
public struct PublicKeyCredential<T: AuthenticatorResponse>: Codable {
    /// Contains the type of the public key credential the caller is referring to
    public var type: PublicKeyCredentialType = .publicKey
    
    /// A string represented by the credential identifier.
    public var rawId: String
    
    /// Contains the credential ID of the public key credential the caller is referring to
    public var id: String
    
    /// Contains the authenticator's response to the client’s request to either create a public key credential, or generate an authentication assertion.
    public var response: T
    
    /// Contains the results of processing client extensions requested by the Relying Party
    public var getClientExtensionResults = ClientExtensionResults()
    
    /// Contains a hint as to how the client might communicate with the managing authenticator of the public key credential the caller is referring to.
    public var getTransports: [String]? = nil
    
    /// Client extensions requested by the Relying Party.
    public struct ClientExtensionResults: Codable {}
}


// MARK: Enums

/// An enumeration for defining valid credential types.
public enum PublicKeyCredentialType: String, Codable {
    /// Credential type is defined as "public-key".
    case publicKey = "public-key"
}

/// An enumeraton for defining credential passing preferences, which are used by the WebAuthn relying party when the credential is created.
public enum AttestationConveyancePreference: String, Codable {
    /// This value indicates that the relying party is not interested in authenticator attestation.
    case none
    
    /// This value indicates that the relying party prefers an attestation conveyance yielding verifiable attestation object, but allows the client to decide how to obtain such an attestation object.
    case indirect
    
    /// This value indicates that the relying party wants to receive the attestation object as generated by the authenticator.
    case direct
}

/// The value of a `COSEAlgorithmIdentifier` is a number identifying a cryptographic algorithm.
/// - Remark: See [https://www.iana.org/assignments/cose/cose.xhtml#algorithms](https://www.iana.org/assignments/cose/cose.xhtml#algorithms)
public enum COSEAlgorithmIdentifier: Int, Codable {
    /// RSASSA-PKCS1-v1_5 using SHA-1
    case rs1 = -65535
    
    /// RSASSA-PKCS1-v1_5 using SHA-256
    case rs256 = -257
    
    /// RSASSA-PKCS1-v1_5 using SHA-384
    case rs384 = -258
    
    /// RSASSA-PKCS1-v1_5 using SHA-512
    case rs512 = -259
    
    /// ECDSA using secp256k1 curve and SHA-256
    case es256 = -7
    
    /// ECDSA with SHA-384
    case es384 = -35
    
    /// ECDSA with SHA-512
    case es512 = -36
    
    /// RSASSA-PSS with SHA-256
    case ps256 = -37
    
    /// Gets the COSE value for the algorithm used in the encryption of the credential.
    /// - Parameter value: A value to match the algorithm identifier.
    /// - Returns: A `COSEAlgorithmIdentifier` otherwise `nil`.
    public static func parse(from value: Int) -> COSEAlgorithmIdentifier? {
        switch value {
        case self.rs1.rawValue:
            return self.rs1
        case self.rs256.rawValue:
            return self.rs256
        case self.rs384.rawValue:
            return self.rs384
        case self.rs512.rawValue:
            return self.rs512
        case self.es256.rawValue:
            return self.es256
        case self.es384.rawValue:
            return self.es384
        case self.es512.rawValue:
            return self.es512
        case self.ps256.rawValue:
            return self.ps256
        default:
            return nil
        }
    }
}

/// An enumeration that defines how clients might communicate with an authenticator in order to obtain an assertion for a specific credential.
public enum AuthenticatorTransport: String, Codable {
    /// Authenticator can be contacted over removable USB.
    case usb
    
    /// Authenticator can be contacted over Near Field Communication (NFC).
    case nfc
    
    /// Authenticator can be contacted over Bluetooth Low Energy (BLE).
    case ble
    
    /// Authenticator can be contacted over ISO/IEC 7816 smart card with contacts.
    case smartcard = "smart-card"
    
    /// Authenticator can be contacted using a combination of (often separate) data-transport and proximity mechanisms. This supports, for example, authentication on a desktop computer using a smartphone.
    case hybrid
    
    /// Authenticator is contacted using a client device-specific transport, i.e a platform authenticator. These authenticators are not removable from the client device.
    case `internal` = "internal"
}

/// An enumeration that describes an authenticators' attachment modalities. Relying parties use this to express a preferred authenticator attachment modality.
public enum AuthenticatorAttachment: String, Codable {
    /// A platform authenticator is attached using a client device-specific transport, called platform attachment, and is usually not removable from the client device.
    /// - Remark: A public key credential bound to a platform authenticator is called a platform credential.
    case platform
    
    /// A cross-platform attachment are removable authenticator from, and can "roam" between, client devices.
    ///
    /// A public key credential bound to a roaming authenticator is called a roaming credential.
    case crossPlatform = "cross-platform"
}

/// An enumeration a WebAuthn relying party may require for user verification for some of its operations but not for others, and may use this type to express its needs.
public enum UserVerificationRequirement: String, Codable {
    /// This value indicates that the relying party requires user verification for the operation and will fail the operation if the response does not have the UV flag set.
    case required
    
    /// This value indicates that the relying party prefers user verification for the operation if possible, but will not fail the operation if the response does not have the UV flag set.
    case preferred
    
    /// This value indicates that the Relying Party does not want user verification employed during the operation (e.g., in the interest of minimizing disruption to the user interaction flow).
    case discouraged
}

