//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import Foundation
import Authentication
import Core
import CryptoKit

// MARK: Enums

/// Represents supported hash algorithms used for signing or verification.
///
/// This enum maps various string representations (e.g., `"SHA256"`, `"RSASHA256"`) to canonical algorithm types. It supports decoding from external sources and ensures consistent internal usage.
public enum SigningAlgorithm: String, Codable {
    /// SHA-1 hashing (160-bit digest).
    /// ⚠️ Not considered cryptographically secure. Included for legacy compatibility.
    case sha1
    
    /// SHA-256 hashing (256-bit digest).
    case sha256
    
    /// SHA-384 hashing (384-bit digest).
    case sha384
    
    /// SHA-512 hashing (512-bit digest).
    case sha512
    
    /// Maps common algorithm strings to their canonical enum case.
    private static let aliases: [String: SigningAlgorithm] = [
        "SHA1": .sha1, "HMACSHA1": .sha1, "RSASHA1": .sha1, "SHA1WITHRSA": .sha1,
        "SHA256": .sha256, "HMACSHA256": .sha256, "RSASHA256": .sha256, "SHA256WITHRSA": .sha256,
        "SHA384": .sha384, "HMACSHA384": .sha384, "RSASHA384": .sha384, "SHA384WITHRSA": .sha384,
        "SHA512": .sha512, "HMACSHA512": .sha512, "RSASHA512": .sha512, "SHA512WITHRSA": .sha512
    ]
    
    /// Initializes a `HashAlgorithmType` from a flexible string representation.
    ///
    /// - Parameter rawValue: A string such as `"SHA256"`, `"RSASHA256"`, or `"SHA256WITHRSA"`.
    /// - Returns: A valid `HashAlgorithmType` or `nil` if the input is unrecognized.
    public init?(from rawValue: String) {
        let normalized = rawValue.uppercased()
        guard let matched = SigningAlgorithm.aliases[normalized] else {
            return nil
        }
        self = matched
    }
    
    /// A computed property that returns the appropriate CryptoKit hash function for the enum case.
    internal var hashFunction: any HashFunction.Type {
        switch self {
        case .sha1:
            return Insecure.SHA1.self
        case .sha256:
            return SHA256.self
        case .sha384:
            return SHA384.self
        case .sha512:
            return SHA512.self
        }
    }
    
    /// Returns the canonical algorithm identifier expected by the server.
    ///
    /// While `SigningAlgorithm` supports flexible inbound parsing through `init?(from:)`—allowing values such as `"SHA256"`, `"RSASHA256"`, or `"SHA256WITHRSA"` to map to the same enum case—the server requires a single, authoritative outbound string for each algorithm.
    ///
    /// The `cloudValue` property provides this canonical representation. It ensures that all outbound enrollment requests use a consistent, server‑approved format (e.g., `"RSASHA256"`), regardless of how the algorithm was originally specified or parsed.
    ///
    /// ```swift
    /// let algorithm = SigningAlgorithm.sha256
    /// let outbound = algorithm.cloudValue   // "RSASHA256"
    /// ```
    ///
    /// - Returns: A server‑compatible algorithm identifier string.
    internal var cloudValue: String {
        switch self {
        case .sha256:
            return "RSASHA256"
        case .sha384:
            return "RSASHA384"
        case .sha512:
            return "RSASHA512"
        default:
            return "RSASHA256"
        }
    }
    
    /// Returns the canonical algorithm identifier expected by the server.
    ///
    /// While `SigningAlgorithm` supports flexible inbound parsing through `init?(from:)`—allowing values such as `"SHA256"`, `"RSASHA256"`, or `"SHA256WITHRSA"` to map to the same enum case—the server requires a single, authoritative outbound string for each algorithm.
    ///
    /// The `onPremiseValue` property provides this canonical representation. It ensures that all outbound enrollment requests use a consistent, server‑approved format (e.g., `"SHA256WITHRSA"`), regardless of how the algorithm was originally specified or parsed.
    ///
    /// ```swift
    /// let algorithm = SigningAlgorithm.sha256
    /// let outbound = algorithm.onPremiseValue   // "SHA256WITHRSA"
    /// ```
    ///
    /// - Returns: A server‑compatible algorithm identifier string.
    internal var onPremiseValue: String {
        switch self {
        case .sha256:
            return "SHA256withRSA"
        case .sha384:
            return "SHA384withRSA"
        case .sha512:
            return "SHA512withRSA"
        default:
            return "SHA512withRSA"
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
    
    /// A signature factor requiring a biometric challenge, refers to the use of a digital signature as a second factor to authenticate an external entity.
    var biometric: BiometricFactorInfo? { get }
    
    /// A signature factor refers to the use of a digital signature as a second factor to authenticate an external entity.
    var userPresence: UserPresenceFactorInfo? { get }
}

extension MFAAuthenticatorDescriptor {
    /// Returns all available enrolled signature factors for an authenticator.
    ///
    /// This property normalizes the authenticator’s `biometric` and `userPresence` properties into a single, flat collection of `FactorType` values. Each non‑nil factor is wrapped in its corresponding`FactorType` case, allowing callers to work with a unified list rather than checking each factor manually.
    ///
    /// `allFactors` is especially useful when performing lookups—such as matching a transaction’s `keyName`—because it removes the need for branching logic and force‑unwraps.
    ///
    /// ```swift
    ///     let factor = authenticator.enrolledFactors.first { $0.name == transaction.keyName }
    /// ```
    /// - Returns: An array of all currently available authentication factors.
    public var enrolledFactors: [FactorType] {
        [
            biometric.map { .biometric($0) },
            userPresence.map { .userPresence($0) }
        ].compactMap { $0 }
    }
}

// MARK: - Structures

/// Represents a single signature-based authentication method.
struct SignatureMethod: Decodable {
    /// The location of the authentication method enrollment endpoint
    let enrollmentUri: URL
    
    /// Additional attributes for a signature based authentication method.
    let attributes: SignatureAttributes? // Attributes may not always be present
    
    /// Indicates if the authentication method is enabled
    let enabled: Bool
}

/// Contains the attributes for a signature-based authentication method.
struct SignatureAttributes: Decodable {
    /// A list of supported signing algorithms
    let supportedAlgorithms: [String]
    
    /// The preferred signing algorithm.
    let algorithm: String
}

// MARK: - Functions

/// Creates a new RSA private key and securely stores in the Keychain.
/// - Parameters:
///   - name: A unique identifier for the key pair. Used for storing and retrieving the private key.
///   - biometricAuthentication: If `true`, biometric authentication will be required to access the private key.
/// - Returns: The generated RSA private key object. The public key can be accessed via `privateKey.publicKey`.
/// - Throws: An error if the key cannot be stored or if access control fails.
internal func storeBiometricPrivateKey(data: Data) throws -> String {
    let name = "biometric"
    try KeychainService.default.addItem(name, value: data, accessControl: .userPresence)
    return name
}

/// Retrieves the RSA private key from the Keychain.
/// - Parameters:
///   - name: A unique identifier for the private key.
/// - Returns: The generated RSA private key object.
/// - Throws: An error if the key cannot be retrieved or decoded.
internal func retrievePrivateKey(name: String) throws -> RSA.Signing.PrivateKey {
    let keyData = try KeychainService.default.readItem(name, searchType: .key)
    return try RSA.Signing.PrivateKey(derRepresentation: keyData)
}
    
/// Signs a UTF-8 string using the provided RSA private key and specified hashing algorithm.
///
/// This method performs the following steps:
/// 1. Converts the input string into UTF-8 data.
/// 2. Hashes the data using the specified algorithm.
/// 3. Signs the hash using the RSA private key.
/// 4. Returns the signature as a base64url-encoded string.
///
/// - Parameters:
///   - dataToSign: The string to be signed.
///   - privateKey: The RSA private key.
///   - signingAlgorithm: The hashing algorithm to use before signing.
/// - Returns: A base64url-encoded signature string.
/// - Throws: `MFAServiceError.dataConversionFailed` if the string cannot be converted to data, or any error thrown during key parsing or signing.
internal func sign(_ dataToSign: String, with privateKey: RSA.Signing.PrivateKey, signingAlgorithm: SigningAlgorithm) throws -> String {
    // Convert the input string into UTF-8 encoded data
    guard let messageData = dataToSign.data(using: .utf8) else {
        throw MFAServiceError.dataDecodingFailed(reason: String(localized: "Failed to convert data to UTF-8 string.", bundle: .module))
    }
    
    // Hash the message data using the specified algorithm
    let hashedData = signingAlgorithm.hashFunction.hash(data: messageData)
    
    // Sign the hashed data using the RSA private key
    let signature = try privateKey.signature(for: hashedData)
    
    // Return the signature as a base64url-encoded string
    return signature.rawRepresentation.base64UrlEncodedString()
}
