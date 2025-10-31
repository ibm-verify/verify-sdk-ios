//
// Copyright contributors to the IBM Verify FIDO2 SDK for iOS project
//

import Foundation
import CryptoKit
import os.log

// MARK: Protocols

/// Declares that a type can generate an attestation format.
public protocol AttestionStatementProvider {
    /// The AAGUID of the authenticator.
    var aaguid: UUID {
        get
    }
    
    /// The attestation format of the contextual binding of the authenticator.
    var format: String {
        get
    }
    
    /// Create an attestation statement format which represents a cryptographic signature by an authenticator over a set of contextual bindings.
    /// - Returns: A dictionary represenitng the attestation statement format.
    func statement() throws -> Dictionary<String, Any>
}

/// This is a WebAuthn optimized attestation statement format. It uses a very compact but still extensible encoding method.
///
/// If self attestation is in use, the authenticator produces `sig` by concatenating `authenticatorData` and `clientDataHash`, and signing the result using the credential private key. It sets `alg` to the algorithm of the credential private key and omits the other fields.
///
/// Where a certificate based attestation is in use (Basic), the authenticator produces the `sig` by concatenating `authenticatorData` and `clientDataHash`, and signing the result using an attestation private key selected through an authenticator-specific mechanism. It sets `x5c` to `attestnCert` followed by the related certificate chain (if any). It sets `alg` to the algorithm of the attestation private key.
///
/// For more information, see [Packed Attestation Statement Format](https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation).
public protocol PackedAttestionStatementProvider: AttestionStatementProvider {
    /// A byte array containing authenticator data.
    var authenticatorData: Data? {
        get
        set
    }
    
    /// The hash of the serialized client data.
    var clientDataHash: Data? {
        get
        set
    }
}

// MARK: Implementations

/// Self attestation where, the authenticator does not have any specific attestation key pair. Instead it uses the credential private key to create the attestation signature. Authenticators without meaningful protection measures for an attestation private key typically use this attestation type.
public struct SelfAttestation: PackedAttestionStatementProvider {
    // MARK: Initializer
    
    /// Initializes a new `SelfAttestation` instance.
    /// - Parameter aaguid: The AAGUID of the authenticator.
    public init(_ aaguid: UUID) {
        self.aaguid = aaguid
    }
    
    // MARK: Properties
    
    /// The AAGUID of the authenticator.
    public let aaguid: UUID
    
    /// The attestation format of the contextual binding of the authenticator.
    /// - Remark: The value is **packed**
    public let format: String = "packed"
    
    /// A credential private key is the private key portion of a credential key pair. The credential private key is bound to a particular authenticator.
    public var privateKey: SecureEnclave.P256.Signing.PrivateKey?
    
    /// A byte array containing authenticator data.
    public var authenticatorData: Data?
    
    /// The hash of the serialized client data.
    public var clientDataHash: Data?
    
    // MARK: Methods
    
    /// Create an attestation statement format which represents a cryptographic signature by an authenticator over a set of contextual bindings.
    /// - Returns: A dictionary representing the attestation statement format.
    public func statement() throws -> Dictionary<String, Any> {
        var result = [String: Any]()
        result.updateValue(Int64(-7), forKey: "alg")
                
        guard let authenticatorData = authenticatorData, let clientDataHash = clientDataHash else {
            throw PublicKeyCredentialError.invalidAttestationData
        }
        
        guard let privateKey = privateKey else {
            throw PublicKeyCredentialError.invalidPrivateKeyData
        }
        
        // The signature base string
        var data: [UInt8] = []
        data.append(contentsOf: authenticatorData)
        data.append(contentsOf: clientDataHash)
        os_log("Attestation signature string.\n%{public}@.", log: .webauthn, type: .debug, data)
        
        // Perform signing operation
        do {
            let signatureData = try privateKey.signature(for: data).derRepresentation
            let signatureBytes = [UInt8](signatureData)
            result.updateValue(signatureBytes, forKey: "sig")
            return result
        }
        catch let error {
            throw error
        }
    }
}

/// A X.509 Certificate for the attestation key pair used by an authenticator to attest to its origin for example self-signed certificates or certificates generated via white box encryption. At registration time, the authenticator uses the attestation private key to sign the Relying Party-specific credential public key (and additional data) that it generates and returns via the authenticatorMakeCredential operation.
public struct BasicAttestation: PackedAttestionStatementProvider {
    // MARK: Initializer
    
    /// Initializes a new `BasicAttestation` instance.
    /// - Parameters:
    ///   - aaguid: The AAGUID of the authenticator.
    ///   - base64PrivateKey: A credential private key is the private key portion of a credential key pair.
    ///   - base64Certificate: The private certificate in privacy enhanced mail (PEM) format.
    public init(_ aaguid: UUID, base64PrivateKey: String, base64Certificate: String) {
        self.aaguid = aaguid
        self.base64PrivateKey = base64PrivateKey
        self.base64Certificate = base64Certificate
    }
    
    // MARK: Properties
    
    /// The AAGUID of the authenticator.
    public let aaguid: UUID
    
    /// The attestation format of the contextual binding of the authenticator.
    /// - Remark: The value is **packed**.
    public let format: String = "packed"
    
    /// A credential private key is the private key portion of a credential key pair. The credential private key is bound to a particular authenticator.
    /// - Remark: This is the base-64 encoded version of the bytes:
    /// `0x04 + X + Y + D`, where
    /// - `X` is the x-coordinate of the public key
    /// - `Y` is the y-coordinate of the public key
    /// - `D` is the private key bytes
    ///
    /// - Note:  `X`, `Y` and `D` are all 32 bytes exactly, so the total encoded bytes is `3 * 32 + 1 = 97`.
    public let base64PrivateKey: String
    
    /// The private certificate in privacy enhanced mail (PEM) format.
    public let base64Certificate: String
    
    /// A byte array containing authenticator data.
    public var authenticatorData: Data?
    
    /// The hash of the serialized client data.
    public var clientDataHash: Data?
    
    // MARK: Methods
    
    /// Create an attestation statement format which represents a cryptographic signature by an authenticator over a set of contextual bindings.
    /// - Returns: A dictionary represenitng the attestation statement format.
    public func statement() throws -> Dictionary<String, Any> {
        var result = [String: Any]()
        result.updateValue(Int64(-7), forKey: "alg")
        
        // Create a private key for signing.
        var error: Unmanaged<CFError>?
        
        guard let authenticatorData = authenticatorData, let clientDataHash = clientDataHash else {
            throw PublicKeyCredentialError.invalidAttestationData
        }
        
        guard let privateKeyData = Data(base64Encoded: base64PrivateKey) else {
            throw PublicKeyCredentialError.invalidPrivateKeyData
        }
        
        guard let privateKey = SecKeyCreateWithData(privateKeyData as CFData, [kSecAttrType: kSecAttrKeyTypeEC,
                                                                       kSecAttrKeyClass: kSecAttrKeyClassPrivate] as CFDictionary, &error) else {
            os_log("SecKeyCreateWithData Error %{public}@", log: .webauthn, type: .debug, error.debugDescription)
            throw PublicKeyCredentialError.unableToCreateKey
        }
    
        // Build x5c with packed attestation certificate.
        guard let certificateData = Data(base64Encoded: base64Certificate
                                                        .replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "")
                                                        .replacingOccurrences(of: "-----END CERTIFICATE-----", with: "")
                                                        .replacingOccurrences(of: "\n", with: "")) else {
            throw PublicKeyCredentialError.invalidCertificate
        }
            
        result.updateValue([[UInt8](certificateData)], forKey:"x5c")
        
        // The signature base string
        var data: [UInt8] = []
        data.append(contentsOf: authenticatorData)
        data.append(contentsOf: clientDataHash)
        os_log("Attestation signature string \n%{public}@.", log: .webauthn, type: .debug, data)
        
        // Perform signing operation
        guard let signature = SecKeyCreateSignature(privateKey,
                                                  .ecdsaSignatureMessageX962SHA256,
                                                  Data(data) as CFData,
                                                  &error), let signatureData = signature as Data? else {
            os_log("SecKeyCreateSignature Error \n%{public}@", log: .webauthn, type: .debug, error.debugDescription)
            throw PublicKeyCredentialError.unableToCreateSignature
        }
            
        os_log("Signature \n%{public}@", log: .webauthn, type: .debug, "\(signature)")
                    
        let signatureBytes = [UInt8](signatureData)
        result.updateValue(signatureBytes, forKey: "sig")
        return result
    }
}

/// The none attestation statement format is used to replace any authenticator-provided attestation statement when a WebAuthn Relying Party indicates it does not wish to receive attestation information.
///
/// For more information, see [None Attestation Statement Format](https://www.w3.org/TR/webauthn-2/#sctn-none-attestation).
public struct NoneAttestation: AttestionStatementProvider {
    // MARK: Initializer
    
    /// Initializes a new `NoneAttestation` instance.
    public init() {
        self.aaguid = UUID().empty
    }
    
    // MARK: Properties
    
    /// The AAGUID of the authenticator.
    /// - Remark: The value is empty `UUID`.
    public let aaguid: UUID
    
    /// The attestation format of the contextual binding of the authenticator.
    /// - Remark: The value is **none**.
    public let format: String = "none"
    
    // MARK: Methods
    
    /// Create an attestation statement format which represents a cryptographic signature by an authenticator over a set of contextual bindings.
    /// - Returns: A dictionary represenitng the attestation statement format.
    /// - Remark: Returns an empty dictionary.
    public func statement() -> Dictionary<String, Any> {
       return [String: Any]()
    }
}
