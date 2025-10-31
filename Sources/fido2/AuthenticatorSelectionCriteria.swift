//
// Copyright contributors to the IBM Verify FIDO2 SDK for iOS project
//

import Foundation

/// WebAuthn Relying Parties may use the `AuthenticatorSelectionCriteria` dictionary to specify their requirements regarding authenticator attributes.
public struct AuthenticatorSelectionCriteria: Codable {
    /// An enumeration that describes an authenticators' attachment modalities. Relying parties use this to express a preferred authenticator attachment modality. Default is `AuthenticatorAttachment.platform`.
    public let authenticatorAttachment: AuthenticatorAttachment
    
    /// A flag for backwards compatibility with WebAuthn Level 1.  Default is **false**.
    public let requireResidentKey: Bool
    
    /// Describes the Relying Party's requirements regarding user verification for the create() operation. Default is `UserVerificationRequirement.preferred`.
    public var userVerification: UserVerificationRequirement
    
    /// Creates a new `AuthenticatorSelectionCriteria` instance.
    /// - Parameters:
    ///   - authenticatorAttachment: An enumeration that describes an authenticators' attachment modalities. Relying parties use this to express a preferred authenticator attachment modality.  `AuthenticatorAttachment.platform`.
    ///   - requireResidentKey: A flag for backwards compatibility with WebAuthn Level 1.  Default is **false**.
    ///   - userVerification: Describes the Relying Party's requirements regarding user verification for the create() operation.  Default is `UserVerificationRequirement.preferred`.
    public init(authenticatorAttachment: AuthenticatorAttachment = .platform,
                requireResidentKey: Bool = false,
                userVerification: UserVerificationRequirement = .preferred) {
        self.authenticatorAttachment = authenticatorAttachment
        self.requireResidentKey = requireResidentKey
        self.userVerification = userVerification
    }
    
    enum CodingKeys: String, CodingKey {
        case authenticatorAttachment, requireResidentKey, userVerification
    }
    
    /// Creates a new instance by decoding from the given decoder
    /// - Parameter decoder: The decoder to read data from.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        authenticatorAttachment = try container.decodeIfPresent(AuthenticatorAttachment.self, forKey: .authenticatorAttachment) ?? .platform
        requireResidentKey = try container.decodeIfPresent(Bool.self, forKey: .requireResidentKey) ?? false
        userVerification = try container.decodeIfPresent(UserVerificationRequirement.self, forKey: .userVerification) ?? .preferred
    }
}

