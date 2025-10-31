//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import Foundation
import Authentication

/// The `CloudAuthenticator` enables authenticators to be able to perform transaction and token refresh operations.
public struct CloudAuthenticator: MFAAuthenticatorDescriptor {
    public let refreshUri: URL
    public let transactionUri: URL
    public var theme: [String: String]
    public var token: TokenInfo
    public let id: String
    public let serviceName: String
    public var accountName: String
    public let allowedFactors: [FactorType]
    public var publicKeyCertificate: String?
    
    /// A key value pair for configuring custom attributes of the authenticator.
    public let customAttributes: [String: String]
}
