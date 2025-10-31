//
// Copyright contributors to the IBM Verify Authentication SDK for iOS project
//

import Foundation
import CryptoKit

/// Proof Key for Code Exchange (PKCE) by OAuth 2.0 public clients.
///
/// Where an OpenID Connect service provider has configured PKCE for authorization code-flow operations, generate a code verifier and code challenge.  For example:
/// ```swift
/// let codeVerifier = PKCE.generateCodeVerifier()
/// let codeChallenge = PKCE.generateCodeChallenge(from: codeVerifier)
///
/// print("SHA256 hash of codeVerifier: \(codeChallenge)")
/// ```
public enum PKCE {
    /// Generates a cryptographically random string that is used to correlate the authorization request to the token request.
    /// - Returns: A cryptographically random string.
    public static func generateCodeVerifier() -> String {
        var buffer = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, buffer.count, &buffer)
        return Data(buffer).base64UrlEncodedString(options: [.noPaddingCharacters, .safeUrlCharacters])
    }

    /// A challenge derived from the code verifier that is sent in the authorization request, to be verified against later.
    /// - Parameter codeVerifier: A cryptographically random string.
    /// - Returns: Returns a Base-64 URL encoded string
    public static func generateCodeChallenge(from codeVerifier: String) -> String? {
        guard let data = codeVerifier.data(using: .utf8) else {
            return nil
        }
        
        let digest = SHA256.hash(data: data)
        return Data(digest).base64UrlEncodedString(options: [.noPaddingCharacters, .safeUrlCharacters])
    }
}
