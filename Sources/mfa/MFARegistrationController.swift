//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import Foundation
import Core
import CryptoKit

// MARK: Enums

/// A type that indicates when a registration fails.
public enum MFARegistrationError: Error, LocalizedError, Equatable {
    /// Returns a Boolean value indicating whether two values are equal.
    /// - Parameters:
    ///   - lhs: A value to compare.
    ///   - rhs: Another value to compare.
    public static func == (lhs: MFARegistrationError, rhs: MFARegistrationError) -> Bool {
        return lhs.localizedDescription == rhs.localizedDescription
    }
    
    /// An error that occurs when a JSON value fails to parse as the specified type.
    case failedToParse
    
    /// Invalid JSON format to create an ``MFARegistrationDescriptor``.
    case invalidFormat
    
    /// An error that occurs when the registration provider has no factors available for enrollment.
    case noEnrollableFactors
    
    /// An error occured enrolling the factor.
    case enrollmentFailed
    
    /// The initialization fails for some reason (for example if data does not represent valid data for encoding).
    case dataInitializationFailed
    
    /// An error that occurs when the `authenticator_id` is missing from the OAuth token.
    case missingAuthenticatorIdentifier
    
    /// Invalid multi-factor registration data.
    case invalidRegistrationData

    /// A general registration error ocurred.
    case underlyingError(error: Error)
}

// MARK: - Alias

/// A type that represents an enrollable signature.
///
/// `EnrollableSignature` is a type alias for specifying the use of public-key cryptography as a second factor to authenticate an external entity.
/// - Parameters:
///   - biometricAuthentication: A flag to indicate the user should be prompted for biometric authenticate before saving the private key.
///   - algorithm: The  hash algorithm to use when generating the keys.
///   - dataToSign: A value that is to be signed with the generated private key.
public typealias EnrollableSignature = (biometricAuthentication: Bool, algorithm: HashAlgorithmType, dataToSign: String)

// MARK: - Protocols

/// An interface that registration providers implement to perform enrollment operations.
public protocol MFARegistrationDescriptor {
    associatedtype Authenticator: MFAAuthenticatorDescriptor
    
    /// A token that identifies the device to Apple Push Notification Service (APNS).
    ///
    /// Communicate with Apple Push Notification service (APNs) and receive a unique device token that identifies your app.  Refer to [Registering Your App with APNs](https://developer.apple.com/documentation/usernotifications/registering_your_app_with_apns).
    var pushToken: String {
        get
        set
    }
    
    /// The account name associated with the service.
    var accountName: String {
        get
        set
    }
    
    /// The number of signatures available for enrollment.
    var countOfAvailableEnrollments: Int {
        get
    }
    
    /// Creates the instance with JSON value.
    /// - Parameters:
    ///   - value: The JSON value typically obtained from a QR code.
    init(json value: String) throws

    /// Gets the next available factor for enrollment.
    ///
    /// The function defined here returns ``EnrollableSignature`` which is used to create a public-key and sign the data. For example:
    /// ```swift
    /// let controller = MFARegistrationController(json: qrScanResult)
    ///
    /// // Initiate the registration provider.
    /// let provider = try await controller.initiate(with: "John Doe", pushToken: "abc123")
    ///
    /// // Get the next enrollable signature.
    /// guard let factor = await provider.nextEnrollment() else {
    ///    return
    /// }
    ///
    /// // Create the key-pair using default SHA512 hash.
    /// let key = RSA.Signing.PrivateKey()
    /// let publicKey = key.publicKey
    ///
    /// // Sign the data with the private key.
    /// let value = factor.dataToSign.data(using: .utf8)!
    /// let signature = try key.signature(for: value)
    ///
    /// // Add to the Keychain.
    /// try KeychainService.default.addItem("biometric",
    ///    value: key.derRepresentation,
    ///    accessControl: factor.biometricAuthentication ? .biometryCurrentSet : nil)
    ///
    /// // Enroll the factor.
    /// try await provider.enroll(with: "biometric",
    ///    publicKey: key.publicKey.x509Representation
    ///    signedData: String(decoding: signature.rawRepresentable, as: UTF8.self)
    /// ```
    ///
    ///  - Returns:An ``EnrollableSignature`` that is used to create the key pair.
    @discardableResult
    func nextEnrollment() async -> EnrollableSignature?
    
    /// Performs the enrollment of the factor.
    ///
    /// This method will generate a private/public key pair.  The private key is automatically saved to the Keychain.
    ///
    /// You can access the private key by name using the `authenticator.id` concatenated with the enrolled factor type.  For example:
    /// ```swift
    /// let controller = MFARegistrationController(json: qrScanResult)
    ///
    /// // Initiate the registration provider.
    /// let provider = try await controller.initiate(with: "John Doe", pushToken: "abc123")
    ///
    /// // Get the next enrollable signature.
    /// guard let factor = await provider.nextEnrollment() else {
    ///    return
    /// }
    ///
    /// // Enroll the factor.
    /// try await provider.enroll()
    ///
    /// // Finalize the enrollment operations and generate the authenticator.
    /// let authenticator = try await provider.finalize()
    ///
    /// // Get the enrolled face factor and retrieve the name in the Keychain to obtain the private key.
    /// if let enrolledFactor = authenticator.allowedFactors.first(where: { $0.valueType is FaceFactorInfo }), let face = enrolledFactor.valueType as? FaceFactorInfo  {
    ///    print(face[keyPath: \.name])  // prints "<authenicator.id>.face"
    /// }
    /// ```
    func enroll() async throws
    
    /// Performs the enrollment of the factor.
    /// - Parameters:
    ///   - name: The name to identify the Keychain item associated with the factor.
    ///   - publicKey: An RSA public key used to verify cryptographic signatures.
    ///   - signedData: The signed data of `EnrollableSignature.dataToSign` using the generated private key.
    func enroll(with name: String, publicKey: String, signedData: String) async throws
    
    /// Completes the enrollment operations.
    ///
    /// When this function is called an authenticator is generated with the enrolled factors.
    /// - Returns: A ``MFAAuthenticatorDescriptor`` that is used to transaction operation and password-less authentication.
    func finalize() async throws -> Authenticator
}

/// An instance you use to instaniate an ``MFARegistrationDescriptor`` to perform enrollment operations.
public class MFARegistrationController {
    /// The JSON string that initiates the a multi-factor registration.
    private let json: String
    
    /// The domain name supporting multi-factor registration.
    public let domain: String?
    
    /// A Boolean value that indicates whether the authenticator will ignore secure sockets layer certificate challenages.
    ///
    ///  Before invoking `initiate(with:pushToken:additionalData:)` this value can be used to alert the user that the certificate connecting the service is self-signed.
    /// - Remark: When `true` the service is using a self-signed certificate.
    public let ignoreSSLCertificate: Bool
    
    // Creates the instance with JSON value.
    /// - Parameters:
    ///   - value: The JSON value typically obtained from a QR code.
    ///
    /// ```swift
    /// // Value from QR code scan
    /// let qrScanResult = "{"code":"A1B2C3D4","options":"ignoreSslCerts=true","details_url":"https://sdk.verifyaccess.ibm.com/mga/sps/mmfa/user/mgmt/details","version": 1, "client_id":"IBMVerify"}"
    ///
    /// // Create the registration controller
    /// let controller = MFARegistrationController(json: qrScanResult)
    ///
    /// // Instaniate the provider
    /// let provider = await controller.initiate(with: "My Account", pushToken: "abc123")
    ///
    /// // Get the next enrollment
    /// guard let factor = await provider.nextEnrollment() else {
    ///   return // No more enrollments
    /// }
    ///
    /// // Enroll the factor generating the private and public key pairs. Depending on the factor this will prompt for Face ID or Touch ID.
    /// print(factor.biometricAuthentication)
    /// provider.enroll()
    /// ```
    public required init(json value: String) {
        self.json = value
        
        var ignoreSSLCertificate = false
        
        // Check is the JSON can update ignoreSSLCertificate flag.
        if let jsonObject = try? JSONSerialization.jsonObject(with: value.data(using: .utf8)!, options: []) as? [String: Any], let options = jsonObject["options"] as? String {
            ignoreSSLCertificate = options.contains("ignoreSslCerts=true")
        }
        
        var domain: String? = nil
                
        // Check for a host value.
        if let jsonObject = try? JSONSerialization.jsonObject(with: value.data(using: .utf8)!, options: []) as? [String: Any] {
            if let value = jsonObject["registrationUri"] as? String, let url = URL(string: value), let host = url.host {
                domain = host
            }
            else if let value = jsonObject["details_url"] as? String, let url = URL(string: value), let host = url.host {
                domain = host
            }
        }
        
        self.domain = domain
        self.ignoreSSLCertificate = ignoreSSLCertificate
    }

    /// Initiates the registration of a multi-factor authenticator.
    /// - Parameters:
    ///   - accountName: The account name associated with the service.
    ///   - skipTotpEnrollment: A Boolean value that when set to `true` the TOTP authentication method enrollment attempt will be skipped.
    ///   - pushToken: A token that identifies the device to Apple Push Notification Service (APNS).
    ///   - additionalData: (Optional) A dictionary of additional attributes assigned to an on-premise registration.
    ///
    ///Communicate with Apple Push Notification service (APNs) and receive a unique device token that identifies your app.  Refer to [Registering Your App with APNs](https://developer.apple.com/documentation/usernotifications/registering_your_app_with_apns).
    public func initiate(with accountName: String, skipTotpEnrollment: Bool = true, pushToken: String? = "", additionalData: [String: Any]? = nil) async throws -> any MFARegistrationDescriptor {
        if let provider = try? CloudRegistrationProvider(json: self.json) {
            try await provider.initiate(with: accountName, skipTotpEnrollment: skipTotpEnrollment, pushToken: pushToken)
            return provider
        }
        
        if let provider = try? OnPremiseRegistrationProvider(json: self.json) {
            try await provider.initiate(with: accountName, skipTotpEnrollment: skipTotpEnrollment, pushToken: pushToken, additionalData: additionalData)
            return provider
        }
        
        throw MFARegistrationError.invalidFormat
    }
}
