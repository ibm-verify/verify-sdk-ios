//
// Copyright contributors to the IBM Verify FIDO2 Sample App for iOS project
//

import Foundation
import os.log
import FIDO2

// MARK: Enums

/// The attributes that can be returned by the FIDO server for a user.
public enum CredentialUserAttribute: String {
    /// The metadata icon of the authenticator
    case icon
    
    /// The unique identifier of the user.
    case userId
    
    /// The name of the user.
    case username
    
    /// The email of the user.
    case email
    
    /// The friendly name of the registration record
    case nickname
    
    /// The metadata description of the authenticator
    case description
    
    /// The AAGuid of the authenticator used ,
    case aaguid
    
    /// The relying party ID this enrollment belongs to.
    case rpId
    
    /// The format of attestation that was performed ,
    case attestationFormat
    
    /// The type of attestation that was performed ,
    case attestationType
    
    /// The attestation trust path of the authenticator.
    case attestationTrustPath
    
    /// The counter of this authenticator.
    case counter
    
    /// The public key issued by the authenticator.
    case credentialPublicKey
    
    ///  The credential ID of the authenticator
    case credentialId
    
    ///  The authenticator extension for txAuthSimple
    case txAuthSimple
}

// MARK: Protocols
/// The assertion response returned after a `WebAuthnAPIClient.Assertion.get()` operation.
public protocol AssertionResponse: Decodable {
    /// The unique identifier of the user.
    var userId: String {
        get
    }
    
    /// The relying party ID this enrollment belongs to.
    var rpId: String {
        get
    }
    
    /// The friendly name of the registration record.
    var nickname: String {
        get
    }
    
    /// A name-value pair of user related credential attributes.
    var attributes: [CredentialUserAttribute: Any] {
        get
    }
}

/// The assertion response returned after a `WebAuthnAPIClient.Assertion.get()` operation.
public protocol AttestationResponse {
    /// The friendly name of the registration record.
    var nickname: String {
        get
    }
    
    var attestation: PublicKeyCredential<AuthenticatorAttestationResponse> {
        get
    }
}


/// The asstestation response is a placeholder protocol to support IBM Verify on-premise FIDO server implementations
public struct ISVAAttestationResponse: AttestationResponse, Codable {
    public let attestation: PublicKeyCredential<AuthenticatorAttestationResponse>
    public let nickname: String
    
    public init(_ nickname: String, attestation: PublicKeyCredential<AuthenticatorAttestationResponse>) {
        self.nickname = nickname
        self.attestation = attestation
    }
    
    /// Encodes this value into the given encoder.
    /// - parameters to: The encoder to write data to.
    /// - throws: This function throws an error if any values are invalid for the given encoder’s format.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        try container.encode(nickname, forKey: .nickname)
        try attestation.encode(to: encoder)
    }
}

/// The asstestation response is a placeholder protocol to support IBM Verify cloud FIDO server implementations
public struct ISVAttestationResponse: AttestationResponse, Codable {
    public let attestation: PublicKeyCredential<AuthenticatorAttestationResponse>
    public let nickname: String
    public let enabled: Bool
    
    public init(_ nickname: String, enabled: Bool = true, attestation: PublicKeyCredential<AuthenticatorAttestationResponse>) {
        self.nickname = nickname
        self.enabled = enabled
        self.attestation = attestation
    }
    
    /// Encodes this value into the given encoder.
    /// - parameters to: The encoder to write data to.
    /// - throws: This function throws an error if any values are invalid for the given encoder’s format.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        try container.encode(nickname, forKey: .nickname)
        try container.encode(enabled, forKey: .enabled)
        try attestation.encode(to: encoder)
    }
}

// MARK: Structures

/// The `ISVAAssertionResponse` represents a collection of user credential properties associated with the response of a `WebAuthnAPIClient.Assertion.get()` operation.
public struct ISVAAssertionResponse: AssertionResponse {
    /// The name to display representing the user.
    public var displayName: String
    
    /// The email of the user.
    public var email: String
    
    /// The name of the user.
    public var username: String
    
    /// The image associated with the authenticator or service.
    public var userId: String
    
    /// The friendly name of the registration record
    public var nickname: String
    
    /// The relying party ID this enrollment belongs to.
    public var rpId: String = ""
    
    /// A name-value pair of user related credential attributes.
    public var attributes: [CredentialUserAttribute: Any] = [:]
    
    enum CodingKeys: String, CodingKey {
        case user, attributes
    }
    
    enum UserCodingKeys: String, CodingKey {
        case id, name
    }

    enum AttributesCodingKeys: String, CodingKey {
        case responseData, credentialData
    }
    
    enum CredentialDataCodingKeys: String, CodingKey {
        case loginDetails = "fidoLoginDetails"
        case friendlyName = "AUTHENTICATOR_FRIENDLY_NAME"
        case authenticationLevel = "AUTHENTICATION_LEVEL"
        case displayName
        case email
        case icon = "AUTHENTICATOR_ICON"
    }
        
    /// Creates a new instance by decoding from the given decoder
    /// - parameter decoder: The decoder to read data from.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
    
        // User container
        let userContainer = try container.nestedContainer(keyedBy: UserCodingKeys.self, forKey: .user)
        self.userId = try userContainer.decode(String.self, forKey: .id)
        self.username = try userContainer.decode(String.self, forKey: .name)
        
        // Attributes contrainer
        let attributesContainer = try container.nestedContainer(keyedBy: AttributesCodingKeys.self, forKey: .attributes)
        
        // Credential data container
        let credentialDataContainer = try attributesContainer.nestedContainer(keyedBy: CredentialDataCodingKeys.self, forKey: .credentialData)
        self.displayName = try credentialDataContainer.decode(String.self, forKey: .displayName)
        self.email = try credentialDataContainer.decode(String.self, forKey: .email)
        self.nickname = try credentialDataContainer.decode(String.self, forKey: .friendlyName)
        
        // Decode fidoLoginDetails
        let loginDetails = try credentialDataContainer.decode(String.self, forKey: .loginDetails)
        self.attributes = parseLoginDetails(json: loginDetails)
        
        // Get the other properties from the attributes.
        self.rpId = attributes[.rpId] as! String
    }
    
    /// Parse the fidoLoginDetails from JSON into a Dictionary.
    /// - parameter value: The JSON data representing the fido login details.
    /// - returns: Dictionary of `CredentialUserAttribute` keys and values.
    private func parseLoginDetails(json value: String) -> [CredentialUserAttribute: Any] {
        var result = [CredentialUserAttribute: Any]()
        
        guard let data = value.data(using: .utf8) else {
            Logger().debug("Unable to convert JSON string to Data.")
            return result
        }
        
        do {
            // Make sure this JSON is in the format we expect
            if let dictionary = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any] {
                // Read out values and add to return dictionary.
                let requestData = dictionary["requestData"] as! [String: Any]
                print("requestData keys \(requestData.keys)")
                
                if let authData = requestData["authData"] as? [String: Any] {
                    authData.forEach {
                       switch $0.key {
                        case "extensions":
                           let extensions = authData["extensions"] as! [String: Any]
                            result[.txAuthSimple] = extensions["txAuthSimple"] as! String
                        default:
                            break
                        
                        }
                    }
                }
                
                let registration = requestData["registration"] as! [String: Any]
                registration.forEach {
                    switch $0.key {
                    case "metadata":
                        let metadata = registration["metadata"] as! [String: Any]
                        result[.icon] = metadata["icon"] as! String
                        result[.description] = metadata["description"] as! String
                    case "attestationTrustPath":
                        result[.attestationTrustPath] = $0.value
                    case "format":
                        result[.attestationFormat] = $0.value
                    case "attestationType":
                        result[.attestationType] = $0.value
                    case "counter":
                        result[.counter] = $0.value as! Int
                    case "publicKey":
                        result[.credentialPublicKey] = $0.value
                    case "rpId":
                        result[.rpId] = $0.value
                    case "userId":
                        result[.userId] = $0.value
                    case "aaGuid":
                        result[.aaguid] = $0.value
                    case "credentialId":
                        result[.credentialId] = $0.value
                    case "username":
                        result[.username] = $0.value
                    default:
                        break
                    }
                }
            }
        }
        catch let error {
            Logger().debug("Failed to load JSON. \(error.localizedDescription, privacy: .public)")
        }
        
        return result
    }
}

/// The `ISVAssertionResponse` represents a collection of user credential properties associated with the response of a `WebAuthnAPIClient.Assertion.get()` operation.
public struct ISVAssertionResponse: AssertionResponse {
    /// The image associated with the authenticator or service.
    public var userId: String
    
    /// The friendly name of the registration record
    public var nickname: String
    
    /// The relying party ID this enrollment belongs to.
    public var rpId: String = ""
    
    /// The type of authenticator factor.
    public var type: String
    
    /// A name-value pair of user related credential attributes.
    public var attributes: [CredentialUserAttribute: Any] = [:]
    
    enum CodingKeys: String, CodingKey {
        case userId, type, attributes
    }

    enum AttributesCodingKeys: String, CodingKey {
        case attestationType, attestationFormat, nickname, rpId, aaGuid, icon, description
    }
        
    /// Creates a new instance by decoding from the given decoder
    /// - parameter decoder: The decoder to read data from.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
    
        self.userId = try container.decode(String.self, forKey: .userId)
        self.type = try container.decode(String.self, forKey: .type)
        
        // Attributes contrainer
        let attributesContainer = try container.nestedContainer(keyedBy: AttributesCodingKeys.self, forKey: .attributes)
        
        var attributes = [CredentialUserAttribute:Any]()
        attributes[.rpId] = try attributesContainer.decode(String.self, forKey: .rpId)
        attributes[.nickname] = try attributesContainer.decode(String.self, forKey: .nickname)
        attributes[.aaguid] = try attributesContainer.decode(String.self, forKey: .aaGuid)
        attributes[.attestationFormat] = try attributesContainer.decode(String.self, forKey: .attestationFormat)
        attributes[.attestationType] = try attributesContainer.decode(String.self, forKey: .attestationType)
        attributes[.icon] = try attributesContainer.decodeIfPresent(String.self, forKey: .icon)
        attributes[.description] = try attributesContainer.decodeIfPresent(String.self, forKey: .description)
        
        // Get the other properties from the attributes.
        self.rpId = attributes[.rpId] as! String
        self.nickname = attributes[.nickname] as! String
        
        self.attributes = attributes
    }
}

