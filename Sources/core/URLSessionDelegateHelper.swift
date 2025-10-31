//
// Copyright contributors to the IBM Verify Core SDK for iOS project
//

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

import OSLog

/// The `SelfSignedCertificateDelegate` will allow SSL traffic to be transferred using a self signed certificate.
 /// - Remark: Using this class should **ONLY** be used for testing purposes.
public final class SelfSignedCertificateDelegate: NSObject, URLSessionDelegate {
    // MARK: Variables
    private let logger: Logger
    private let serviceName = Bundle.main.bundleIdentifier!
    
    /// Initializes the `SelfSignedCertificateDelegate`.
    public override init() {
        logger = Logger(subsystem: serviceName, category: "networking")
    }
    
    /// Requests credentials from the delegate in response to a session-level authentication request from the remote server.
    /// - Parameters:
    ///   - : The `URLSession` to manage the request.
    ///  - challenge: An object that contains the request for authentication.
    ///   - completionHandler: A handler that your delegate method must call.
    /// - Remark: This completion handler uses `credential`.
    public func urlSession(_: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if let error = challenge.error {
            logger.error("Cancel authentication challenge. \(error.localizedDescription, privacy: .public)")
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            logger.info("SSL certificate trust for the challenge protection space was nil.")
            completionHandler(.performDefaultHandling, nil)
            return
        }

        logger.info("Allowing self-signed certificate to be trusted for challenge.")
        
        completionHandler(.useCredential, URLCredential(trust: serverTrust))
    }
}

/// The `PinnedCertificateDelegate` compares certificate provided by the SSL handshake to a certificate presented by the client.
public final class PinnedCertificateDelegate: NSObject, URLSessionDelegate {
    // MARK: Variables
    private let logger: Logger
    private let serviceName = Bundle.main.bundleIdentifier!
    
    /// A DER (Distinguished Encoding Rules) representation of an X.509 certificate.
    let certificateData: Data

    /// Initializes a `PinnedCertificateDelegate` with a certificate represented as a base64 `String`.
    /// - Parameter certificate: A base64 encoded DER (Distinguished Encoding Rules) representation of an X.509 certificate.
    public init?(with certificate: String) {
        logger = Logger(subsystem: serviceName, category: "networking")
        
        guard let data = Data(base64Encoded: certificate) else {
            logger.error("The base64 encoded certificate was invalid.")
            return nil
        }

        certificateData = data
    }

    /// Requests credentials from the delegate in response to a session-level authentication request from the remote server.
    /// - Parameters:
    ///   - : The session containing the task that requested authentication.
    ///   - : <#parameter description#>
    ///  - challenge: An object that contains the request for authentication.
    ///   - completionHandler: A handler that your delegate method must call.
    public func urlSession(_: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if let error = challenge.error {
            logger.error("Cancel authentication challenge. \(error.localizedDescription, privacy: .public)")
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            // Terminate further processing, no certificate at index 0
            logger.info("SSL certificate trust chain for the challenge protection space was not found.")
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // Compare the presented certificate to the pinned certificate.
        if let certificates = SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate] {
            let serverCertificatesData = Set(
                certificates.map { SecCertificateCopyData($0) as Data }
            )
            
            if serverCertificatesData.contains(certificateData) {
                logger.info("SSL certificate presented in challenge matches the pinned certificate.")
                completionHandler(.useCredential, URLCredential(trust: serverTrust))
                return
            }
        }
        

        // Don't trust the presented certificate by default.
        logger.info("SSL certificate presented in challenge does not match the pinned certificate.")
        completionHandler(.cancelAuthenticationChallenge, nil)
    }
}
