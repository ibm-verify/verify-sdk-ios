//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import Foundation
import Authentication

/// A class representing an on-premise multi-factor authenticator.
///
/// `OnPremiseAuthenticator` manages connection details for self-hosted or corporate authentication services, including support for custom SSL configurations and QR login.
public struct OnPremiseAuthenticator: MFAAuthenticatorDescriptor, Sendable {
    public let refreshUri: URL
    public let transactionUri: URL
    public var theme: [String: String]
    public var token: TokenInfo
    public let id: String
    public var serviceName: String
    public var accountName: String
    public var publicKeyCertificate: String?
    public private(set) var userPresence: UserPresenceFactorInfo?
    public private(set) var biometric: BiometricFactorInfo?
    public let createdDate: Date?
    
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
