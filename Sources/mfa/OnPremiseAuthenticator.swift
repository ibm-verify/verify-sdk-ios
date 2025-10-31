//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import Foundation
import Authentication

/// The `OnPremiseAuthenticator` enables authenticators to be able to perform transaction and token refresh operations.
public struct OnPremiseAuthenticator: MFAAuthenticatorDescriptor {
    public let refreshUri: URL
    public let transactionUri: URL
    public var theme: [String: String]
    public var token: TokenInfo
    public let id: String
    public let serviceName: String
    public var accountName: String
    public let allowedFactors: [FactorType]
    public var publicKeyCertificate: String?
    
    /// The location of the endpoint to perform QR code based authentication.
    ///
    /// This value is determined by server configuration.
    public let qrloginUri: URL?
    
    /// A Boolean value that indicates whether the authenticator will ignore secure sockets layer certificate challenages.
    ///
    /// - remark: When `true` the service is using a self-signed certificate.
    public private(set) var ignoreSSLCertificate: Bool = false
    
    /// The unique identifier between the service and the client app.
    public private(set) var clientId: String
}
