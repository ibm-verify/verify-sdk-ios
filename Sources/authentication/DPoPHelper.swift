//
// Copyright contributors to the IBM Verify Authentication SDK for iOS project
//

import Foundation
import CryptoKit
import Core

/// Demonstrating Proof of Possession (DPoP) is an application-level mechanism for sender-constraining OAuth access and refresh tokens.
///
/// A client can prove the possession of a public/private key pair by including a DPoP header in an HTTP request.  For example:
/// ```swift
/// import Core
///
/// // Create and store the private key.
/// let key = RSA.Signing.PrivateKey()
/// try? KeychainService.default.addItem("myKey", value: key.derRepresentation)
///
/// // Create the DPoP header to obtain an access token from the token endpoint.
/// let result = try DPoP.generateProof(key, uri: "https://server.com/token")
/// let header = ["DPoP": result]
///
/// print(header)
///
/// // Create the follow up request with an access token using an existing private key.
/// guard let data = try? KeychainService.default.readItem("myKey", type: Data.self) else {
///    return
/// }
///
/// let key = try RSA.Signing.PrivateKey(derRepresentation: data)
///
/// // Create the DPoP header with an access token for introspection validation.
/// let result = try DPoP.generateProof(key, uri: "https://example.com/validate", accessToken: "abc123")
/// let header = ["DPoP": result]
///
/// print(header)
/// ```
public enum DPoP {
    /// Generates a DPoP proof to demonstrate possession of a key used to sign the DPoP proof JWT.
    /// - Parameters:
    ///   - privateKey: An RSA private key used to create cryptographic signatures.
    ///   - hashAlgorithm: A type that performs cryptographically secure hashing.
    ///   - uri: A value that identifies the location of a remote server.
    ///   - method: The HTTP request method.
    ///   - accessToken: The access token to associate with the proof.
    /// - Returns: A JSON Web Token (JWT) to be sent with an HTTP request using the DPoP header field..
    public static func generateProof(_ privateKey: RSA.Signing.PrivateKey, hashAlgorithm: any HashFunction = SHA256(), uri: String, method: method = .post, accessToken: String? = nil) throws -> String {
        
        var algorithmName  = "RS256"
        
        switch hashAlgorithm {
        case is SHA256:
            break;
        case is SHA384:
            algorithmName = "RS384"
        case is SHA512:
            algorithmName = "RS512"
        default:
            throw CryptoKitError.incorrectParameterSize
        }
        
        guard let url = URL(string: uri) else {
            throw URLError(.badURL)
        }
        
        let publicKey = privateKey.publicKey
        
        // Create the JWT header containing the algorithm and token type.
        let header = """
        { \
          "alg": "\(algorithmName)", \
          "typ": "dpop+jwt", \
          "jwk": \(publicKey.jwkRepresentation) \
        }
        """.data(using: .utf8)!.base64UrlEncodedString(options: [.noPaddingCharacters, .safeUrlCharacters])
        
        // Create the "ath" claim if an access token is provided.
        var accessTokenClaim = String()
        
        if let accessToken {
            // Hash the access token
            let digest = SHA256.hash(data: Data(accessToken.utf8))
            let result = Data(digest).base64UrlEncodedString(options: [.noPaddingCharacters, .safeUrlCharacters])
            accessTokenClaim = "\"ath\": \"\(result)\","
        }
        
        // Create the JWT payload data.
        let payload = """
        { \
          "jti": "\(UUID().uuidString)", \
          "iat": \(Int(Date().timeIntervalSince1970)), \
          "htm": "\(method.rawValue.uppercased())", \
          \(accessTokenClaim) \
          "htu": "\(url.absoluteString)" \
        }
        """.data(using: .utf8)!.base64UrlEncodedString(options: [.noPaddingCharacters, .safeUrlCharacters])
        
        // Use the hashing algorithm for the header and payload.
        let data = Data("\(header).\(payload)".utf8)
        
        var algorithm = hashAlgorithm
        algorithm.update(data: data)
        let digest = algorithm.finalize()

        // Create the signature, then validate.
        let signature = try privateKey.signature(for: digest)
        let encodedSignature = signature.rawRepresentation.base64UrlEncodedString(options: [.noPaddingCharacters, .safeUrlCharacters])
        
        if !publicKey.isValidSignature(signature, for: digest) {
            throw CryptoKitError.authenticationFailure
        }
        
        // Return the JWT structure.
        return "\(header).\(payload).\(encodedSignature)"
    }
}
