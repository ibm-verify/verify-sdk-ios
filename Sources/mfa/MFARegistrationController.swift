//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import Foundation
import Core
import CryptoKit
import LocalAuthentication

// MARK: Enums

/// A type that indicates errors that can occur during multi-factor authentication (MFA) registration.
public enum MFARegistrationError: Error, LocalizedError {
    /// An error that occurs when a JSON value fails to decode into the expected type.
    case dataDecodingFailed(reason: String)
    
    /// The provided registration data is in an invalid format.
    case invalidRegistrationData(reason: String)
    
    /// The registration has not been initialized. Please call initiate() first.
    case invalidState
    
    /// The provided algorithm is not supported by the factor.
    case invalidAlgorithm(reason: String)
    
    /// An error that occurs when the registration provider has no factors available for enrollment.
    case noEnrollableFactors
    
    /// The signature method has not been enabled.
    case signatureMethodNotEnabled(type: String)
    
    /// The enrollment process for the factor failed. The associated value provides the underlying error.
    case enrollmentFailed(reason: String)
    
    /// The initialization of data fails (e.g., data is not valid for encoding).
    case dataInitializationFailed
    
    /// An error that occurs when the `authenticator_id` is missing from the OAuth token.
    case missingAuthenticatorIdentifier
    
    /// Biometry is not available or not configured on the device.
    case biometryFailed(reason: String)
    
    /// Biometric authentication failed (e.g., user canceled, face not recognized).
    case failedBiometryVerification(reason: String)
    
    /// A general error that occurred during registration. The associated value provides the underlying error.
    case underlyingError(error: Error)
    
    public var errorDescription: String? {
        switch self {
        case .dataDecodingFailed(let reason):
            return String(localized: "The received data could not be parsed. \(reason)", bundle: .module)
        case .invalidRegistrationData(let reason):
            return String(localized: "The registration data is invalid. \(reason)", bundle: .module)
        case .invalidState:
            return String(localized: "The registration has not been initialized. Please call initiate() first.", bundle: .module)
        case .invalidAlgorithm(let reason):
            return reason
        case .noEnrollableFactors:
            return String(localized: "No factors are available for enrollment.", bundle: .module)
        case .signatureMethodNotEnabled(let type):
            return String(localized: "Signature method '\(type)' is not enabled.", bundle: .module)
        case .enrollmentFailed(let reason):
            return reason
        case .dataInitializationFailed:
            return String(localized:"Failed to initialize registration data.", bundle: .module)
        case .missingAuthenticatorIdentifier:
            return String(localized: "The authenticator identifier is missing from the token.", bundle: .module)
        case .biometryFailed(let reason):
            return reason
        case .failedBiometryVerification(reason: let reason):
            return reason
        case .underlyingError(let error):
            return String(localized: "An error occured. \(error.localizedDescription)", bundle: .module)
        }
    }
}

// MARK: - Alias

/// A tuple representing a signature method identifier and its subtype.
///
/// This typealias is used to group the primary key for a signature method (`methodKey`) with its corresponding subtype (`subType`).
///
/// - `methodKey`: The key used to identify the signature method (e.g., `"signature_face"`).
/// - `subType`: A more specific subtype or variant of the method (e.g., `"face"`).
typealias EnrollableSignature = (methodKey: String, subType: String)

// MARK: - Protocols

/// An interface that registration providers implement to perform enrollment operations.
public protocol MFARegistrationDescriptor {
    associatedtype Authenticator: MFAAuthenticatorDescriptor & Codable
    
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
    
    /// Indicates if user presence signature is available for enrollment.
    var canEnrollUserPresence: Bool {
        get
    }
    
    /// Indicates if biometric signature is available for enrollment.
    var canEnrollBiometric: Bool {
        get
    }
    
    /// Creates the instance with JSON value.
    /// - Parameters:
    ///   - value: The JSON value typically obtained from a QR code.
    init(json value: String) throws

    /// Enrolls a signature‑based authentication method.
    ///
    /// The function generates a new private/public key pair, stores the private key using the provided storage function, and then performs the enrollment using the resulting key name and public key.
    ///
    /// The caller supplies a `savePrivateKey` closure, which receives a `SecKeyAddType` describing the private key that should be persisted. In this enrollment flow, the closure will always be invoked with `SecKeyAddType.key`, containing:
    ///  - the raw private key data (`Data`)
    ///  - the key size in bits
    ///  - the algorithm used to generate the key
    ///
    /// ```swift
    /// import Core
    ///
    /// try await enrollUserPresence(
    ///     savePrivateKey: { key in
    ///         // We know only `.key` will be passed
    ///         guard case let .key(value, size, algorithm) = key else {
    ///             throw MFARegistrationError.invalidRegistrationData(reason: "Expected SecKeyAddType.key but received a different case.")
    ///         }
    ///
    ///         // Generate a unique label for the key
    ///         let keyLabel = "\(UUID().uuidString).userPresence"
    ///
    ///         try KeychainService.default.addItem(keyLabel, value: .key(value: value, size: size, algorithm: algorithm))
    ///         return keyLabel
    ///     }
    /// )
    /// ```
    ///
    /// When storing the key, use `SecAccessControlCreateFlags.userPresence` in your `SecAccessControl` configuration. This ensures the key is protected by biometrics with automatic fallback to the device passcode, providing a smooth and secure user experience across Face ID, Touch ID, and PIN‑based verification.  See [SecAccessControlCreateFlags](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags).
    ///
    /// - Parameters:
    ///   - savePrivateKey: A closure that receives the generated private key wrapped in a `SecKeyAddType` and returns the label under which the key was stored. The closure may throw if storage fails.
    /// - Throws: Errors related to biometric evaluation, key generation, or enrollment.
    func enrollUserPresence(savePrivateKey: (SecKeyAddType) throws -> String) async throws
    
    /// Enrolls a signature‑based authentication method requiring biometric verification.
    ///
    /// The function generates a new private/public key pair, stores the private key using the provided storage function, and then performs the enrollment using the resulting key name and public key.
    ///
    /// The caller supplies a `savePrivateKey` closure, which receives a `SecKeyAddType` describing the private key that should be persisted. In this enrollment flow, the closure will always be invoked with `SecKeyAddType.key`, containing:
    ///  - the raw private key data (`Data`)
    ///  - the key size in bits
    ///  - the algorithm used to generate the key
    ///
    /// ```swift
    /// import Core
    ///
    /// try await enrollBiometric(
    ///     savePrivateKey: { key in
    ///         // We know only `.key` will be passed
    ///         guard case let .key(value, size, algorithm) = key else {
    ///             throw MFARegistrationError.invalidRegistrationData(reason: "Expected SecKeyAddType.key but received a different case.")
    ///         }
    ///
    ///         // Generate a unique label for the key
    ///         let keyLabel = "\(UUID().uuidString).biometric"
    ///
    ///         try KeychainService.default.addItem(keyLabel, value: .key(value: value, size: size, algorithm: algorithm))
    ///         return keyLabel
    ///     },
    ///     context: nil,
    ///     reason: "Verify with device authentication"
    /// )
    /// ```
    ///
    /// When storing the key, use `SecAccessControlCreateFlags.userPresence` in your `SecAccessControl` configuration. This ensures the key is protected by biometrics with automatic fallback to the device passcode, providing a smooth and secure user experience across Face ID, Touch ID, and PIN‑based verification.  See [SecAccessControlCreateFlags](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags).
    ///
    /// - Parameters:
    ///   - savePrivateKey: A closure that receives the generated private key wrapped in a `SecKeyAddType` and returns the label under which the key was stored. The closure may throw if storage fails.
    ///   - context: An optional `LAContext`. If `nil`, a new `LAContext()` is created.
    ///   - reason: A localized explanation shown in the biometric prompt.
    /// - Throws: Errors related to biometric evaluation, key generation, or enrollment.
    func enrollBiometric(savePrivateKey: (SecKeyAddType) throws -> String, context: LAContext?, reason: String?) async throws
    
    /// Completes the enrollment operations.
    ///
    /// When this function is called an authenticator is generated with the enrolled factors.
    /// - Returns: A ``MFAAuthenticatorDescriptor`` that is used to transaction operation and password-less authentication.
    func finalize() async throws -> Authenticator
}

extension MFARegistrationDescriptor {
    /// Enrolls a specific signature-based authentication method.
    ///
    /// This method can either generate a new key pair and sign the data itself, or use a pre-existing key pair and signature provided by the caller.
    ///
    /// - Throws: `CloudRegistrationError` or `OnPremisesRegistrationError` for various validation and network failures.
    public func enrollUserPresence() async throws {
        try await enrollUserPresence(
            savePrivateKey: { key in
                // Generate a unique label for the key
                let keyLabel = "\(UUID().uuidString).userPresence"
                
                // Save to Keychain.
                try KeychainService.default.addItem(keyLabel, value: key)
                    
                return keyLabel
            }
        )
    }
    
    /// Enrolls a specific signature-based authentication method requiring biometric verification.
    ///
    /// This method first performs a biometric challenge and then uses the shared enrollment logic to register a signature key that is protected by biometry.
    ///
    /// - Throws: `CloudRegistrationError` or `OnPremisesRegistrationError` for various validation and network failures.
    public func enrollBiometric() async throws {
        try await enrollBiometric(
            savePrivateKey: { key in
                // Generate a unique label for the key
                let keyLabel = "\(UUID().uuidString).biometrics"
                
                // Save to Keychain.
                try KeychainService.default.addItem(keyLabel, value: key, accessControl: .userPresence)
                
                return keyLabel
            },
            context: nil,
            reason: "Verify with device authentication"
        )
    }
}

/// A controller that manages the overall multi-factor registration process.
///
/// This class safely parses the QR code data and orchestrates the initiation of either a cloud or on-premise registration provider.
public class MFARegistrationController {
    // MARK: - Properties
    
    /// The JSON string that initiates the a multi-factor registration.
    private let json: String
    
    /// The domain name supporting multi-factor registration.
    public let domain: String?
    
    /// A Boolean value that indicates whether the authenticator will ignore secure sockets layer certificate challenages.
    ///
    ///  Before invoking ``initiate(with:pushToken:additionalData:)`` this value can be used to alert the user that the certificate connecting the service is self-signed.
    /// - Remark: When `true` the service is using a self-signed certificate.
    public let ignoreSSLCertificate: Bool
    
    // MARK: - Initialization
    
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
    ///   - pushToken: A token that identifies the device to Apple Push Notification Service (APNS).
    ///   - additionalData: (Optional) A dictionary of additional attributes assigned to an on-premise registration.
    ///
    ///Communicate with Apple Push Notification service (APNs) and receive a unique device token that identifies your app.  Refer to [Registering Your App with APNs](https://developer.apple.com/documentation/usernotifications/registering_your_app_with_apns).
    public func initiate(with accountName: String, pushToken: String? = "", additionalData: [String: Any]? = nil) async throws -> any MFARegistrationDescriptor {
        if let provider = try? CloudRegistrationProvider(json: self.json) {
            try await provider.initiate(with: accountName, pushToken: pushToken)
            return provider
        }
        else if let provider = try? OnPremiseRegistrationProvider(json: self.json) {
            try await provider.initiate(with: accountName, pushToken: pushToken, additionalData: additionalData)
            return provider
        }
        else {
            throw MFARegistrationError.invalidRegistrationData(reason: String(localized: "The provided registration data is not valid for either Cloud or On-Premise registration.", bundle: .module))
        }
    }
}
