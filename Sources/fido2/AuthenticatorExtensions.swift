//
// Copyright contributors to the IBM Verify FIDO2 SDK for iOS project
//

import Foundation

/// An extension involves communication with and processing by the client.
/// - Remark: Extensions requested by a relying party may be ignored by the OS and not passed to the authenticator at all, or they may be ignored by the authenticator.
public struct AuthenticatorExtensions: Codable {
    /// A prompt string, intended for display on a trusted device on the authenticator.
    public var txAuthSimple: String
    
    /// Creates a new instance.
    /// - Parameter txAuthSimple: A prompt string, intended for display on a trusted device on the authenticator.
    public init(txAuthSimple: String) {
        self.txAuthSimple = txAuthSimple
    }
}
