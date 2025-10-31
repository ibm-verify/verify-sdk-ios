//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import Foundation
import Authentication
import Core
import CryptoKit

// MARK: Enums

/// General hash algorithm errors used by MFA..
public enum HashAlgorithmError: Error {
    /// The hash type is invalid.
    case invalidHash
}

/// Values indicating the type of hash algorithm to use.
public enum HashAlgorithmType: String, Codable {
    /// SHA1 hashing.
    ///
    /// This hash algorithm isn’t considered cryptographically secure, but is provided for backward compatibility with older services that require it.
    case sha1
    
    /// Secure Hashing Algorithm 2 (SHA-2) hashing with a 256-bit digest.
    case sha256
    
    /// Secure Hashing Algorithm 2 (SHA-2) hashing with a 384-bit digest.
    case sha384
    
    /// Secure Hashing Algorithm 2 (SHA-2) hashing with a 512-bit digest.
    case sha512
    
    /// Instantiates an instance of the conforming type from a string representation.
    /// - Parameters:
    ///   - rawValue: The name of the algorithm.
    public init?(rawValue: String) {
        switch rawValue.uppercased() {
        case "SHA1", "HMACSHA1", "RSASHA1", "SHA1WITHRSA":
            self = .sha1
        case "SHA256", "HMACSHA256", "RSASHA256", "SHA256WITHRSA":
            self = .sha256
        case "SHA384", "HMACSHA384", "RSASHA384", "SHA384WITHRSA":
            self = .sha384
        case "SHA512", "HMACSHA512", "RSASHA512", "SHA512WITHRSA":
            self = .sha512
        default:
            return nil
        }
    }
}

// MARK: - Protocols

/// An interface that defines the authenticator identifier and it's metadata.
public protocol AuthenticatorDescriptor: Identifiable, Codable {
    /// An identifier generated during registration to uniquely identify a specific authenticator.
    ///
    /// The unique identifier of the authenticator.  Typically represented as a `UUID`.
    var id: String { get }
    
    /// The name of the service providing the authenicator.
    var serviceName: String { get }
    
    /// The name of the account associated with the service.
    var accountName: String { get set }
    
    /// A list of allowed factors the user can attempt to perform 2nd factor (2FA) and multi-factor authentication (MFA).
    var allowedFactors: [FactorType] { get }
}

/// An interface that defines a multi-factor authenticator identifier and it's metadata.
public protocol MFAAuthenticatorDescriptor: AuthenticatorDescriptor {
    /// The location of the endpoint to refresh the OAuth token for the authenticator.
    var refreshUri: URL { get }

    /// The location of the endpoint to perform transaction validation.
    var transactionUri: URL { get }

    /// Customizable key value pairs for configuring the theme of the authenticator.
    var theme: [String: String] { get }
    
    /// The authorization server issues an access token and optional refresh token.  In addition the `TokenInfo` provides the token type and other properties supporting the access token.
    var token: TokenInfo { get set }
    
    /// The digital certificate to prove ownership of a public key.
    ///
    /// Where a valid X.509 certificate is provided, the `serverTrustDelegate` is assigned `PinnedCertificateDelegate`.
    ///
    /// - remark: The encoded value of the X.509 certifcate is base64 (ASCII).
    var publicKeyCertificate: String? { get set }
}

/// Generates the private/public key pair returning the public key.
/// - Parameters:
///   - name: A name to identifiy the signature.  The name should be consistent with the key value added to the Keychain to future retrieval.
///   - biometricAuthentication: A flag to indicate the user should be prompted for biometric authenticate before saving the private key.
/// - Returns: The exported public key in x509 format.
internal func generateKeys(name: String, biometricAuthentication: Bool = false) throws -> String {
    let privateKey = RSA.Signing.PrivateKey()
    
    #if targetEnvironment(simulator)
    UserDefaults.standard.set(privateKey.derRepresentation, forKey: name)
    #else
    // Save the private key to the Keychain.
    try KeychainService.default.addItem(name, value: privateKey.derRepresentation, accessControl: biometricAuthentication ? .biometryAny : nil)
    #endif
    
    // Export the public key
    return privateKey.publicKey.x509Representation
}

/// Signs a string value with a private key stored in the Keychain.
/// - Parameters:
///   - name: A name to identifiy the private key stored in the Keychain.
///   - dataToSign: The value to be signed using the private key.
/// - Returns: The exported public key in x509 format.
internal func sign(name: String, algorithm: String, dataToSign: String) throws -> String {
    #if targetEnvironment(simulator)
    let data = UserDefaults.standard.data(forKey: name)!
    #else
    // Retrieve the private key from Keychain
    let data = try KeychainService.default.readItem(name)
    #endif
    
    // Convert to PrivateKey
    let privateKey = try RSA.Signing.PrivateKey(derRepresentation: data)
    
    // Create the signature with the hash
    let hashAlgorithmType = HashAlgorithmType(rawValue: algorithm)
    if hashAlgorithmType == .sha256 {
        let value = SHA256.hash(data:  Data(dataToSign.utf8))
        let signature = try privateKey.signature(for: value)
        return signature.rawRepresentation.base64UrlEncodedString()
    }
    else if hashAlgorithmType == .sha384 {
        let value = SHA384.hash(data:  Data(dataToSign.utf8))
        let signature = try privateKey.signature(for: value)
        return signature.rawRepresentation.base64UrlEncodedString()
    }
    else if hashAlgorithmType == .sha512 {
        let value = SHA512.hash(data:  Data(dataToSign.utf8))
        let signature = try privateKey.signature(for: value)
        return signature.rawRepresentation.base64UrlEncodedString()
    }
    
    throw MFAServiceError.invalidSigningHash
}

/// Looks up the name and algorithm for a given `FactorType`.
/// - Parameters:
///   -  factorType: The type of factor.
/// - Returns: The factor name and hash algorithm, otherwise `nil`.
internal func factorNameAndAlgorithm(for factorType: FactorType) -> (name: String, algorithm: HashAlgorithmType)? {
    switch factorType {
    case .face(let value):
        return (name: value.name, algorithm: value.algorithm)
    case .fingerprint(let value):
        return (name: value.name, algorithm: value.algorithm)
    case .userPresence(let value):
        return (name: value.name, algorithm: value.algorithm)
    default:
        return nil
    }
}
