//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import Foundation
import Authentication
import Core
import CryptoKit
import LocalAuthentication

/// A type that indicates when the cloud registration fails.
public typealias CloudRegistrationError = MFARegistrationError

/// A mechanism for creating a multi-factor authenticator and associated factor enrollments for IBM Verify.
public class CloudRegistrationProvider: MFARegistrationDescriptor {
    public typealias Authenticator = CloudAuthenticator
    
    // MARK: - Initialization
        
    /// Creates the instance with a JSON string value.  The initializer safely decodes the JSON string into an `RegistrationInfo` object.
    ///
    /// - Parameter value: The JSON string value, typically from a QR code.
    /// - Throws: `CloudRegistrationError` if the string cannot be converted to data or if the JSON decoding fails.
    public required init(json value: String) throws {
        // Safely convert the JSON string to Data, throwing an error if it fails.
        guard let data = value.data(using: .utf8) else {
            throw CloudRegistrationError.dataInitializationFailed
        }
        
        let decoder = JSONDecoder()
        
        do {
            // Attempt to decode the data, catching any specific decoding errors.
            let result = try decoder.decode(RegistrationInfo.self, from: data)
            self.registrationInfo = result
            self.accountName = result.accountName
        }
        catch {
            // Re-throw the error as a more descriptive one with the original reason.
            throw CloudRegistrationError.dataDecodingFailed(reason: error.localizedDescription)
        }
    }
    
    /// Initiates the in-app MFA registration process with the provided credentials.
    ///
    /// This function constructs and sends a network request to initiate MFA registration and handles potential network and data-related errors.
    ///
    /// - Parameters:
    ///   - initiateUri: The URL to initiate the registration request.
    ///   - accessToken: The access token for authentication.
    ///   - clientId: The client identifier.
    ///   - accountName: The user's account name.
    /// - Returns: A string representing the successful registration initiation.
    /// - Throws: An `CloudRegistrationError` if the request or data processing fails.
    ///
    /// ```swift
    /// let accountName = "Test Account"
    ///
    /// // Obtain the JSON payload containing the code and registration endpoint.
    /// let initiateUrl = URL(string: "https://tenanturl/v1.0/authenticators/initiation")!
    /// let result = try await CloudRegistrationProvider.inAppInitiate(with: initiateUrl, accessToken: "09876zxyt", clientId: "a8f0043d-acf5-4150-8622-bde8690dce7d", accountName: accountName)
    ///
    /// // Create the registration controller
    /// let provider = try CloudRegistrationProvider(json: result)
    ///
    /// // Instaniate the provider,
    /// try await provider.initiate(with: accountName, pushToken: "abc123")
    /// ```
    public static func inAppInitiate(with initiateUri: URL, accessToken: String, clientId: String, accountName: String) async throws -> String {
        do {
            // Create the request headers.
            let headers = ["Authorization": "Bearer \(accessToken)"]
            
            // Construct the request body.
            let bodyString = """
            {"clientId": "\(clientId)","accountName": "\(accountName)"}
            """
            
            // Ensure the body can be converted to data.
            guard let body = bodyString.data(using: .utf8) else {
                throw CloudRegistrationError.dataInitializationFailed
            }
            
            let resource = HTTPResource<String>(.post,
                                                url: initiateUri,
                                                accept: .json,
                                                contentType: .json,
                                                body: body,
                                                headers: headers) { data, response in
                
                // Ensure data is returned.
                guard let data = data, !data.isEmpty else {
                    return Result.failure(CloudRegistrationError.dataInitializationFailed)
                }
                
                // Convert the data to JSON string.
                guard let value = String(data: data, encoding: .utf8) else {
                    return Result.failure(CloudRegistrationError.dataDecodingFailed(reason: String(localized: "Failed to convert data to UTF-8 string.", bundle: .module)))
                }
                
                return Result.success(value)
            }
            
            return try await URLSession.shared.dataTask(for: resource)
            
        }
        catch {
            // Catch any underlying network or other errors and rethrow them using the general `CloudRegistrationError.underlyingError` case.
            throw CloudRegistrationError.underlyingError(error: error)
        }
    }
    
    // MARK: - Properties
    
    /// The cloud registration information.
    internal let registrationInfo: RegistrationInfo
    
    /// The cloud metedata to enable authentication initialization.
    internal var initializationInfo: InitializationInfo?
    
    /// The access token to authenticate to the cloud service.
    private var token: TokenInfo?
    
    /// A signature factor refers to the use of a digital signature as a second factor to authenticate an external entity.
    private var userPresence: UserPresenceFactorInfo?
    
    /// A signature factor refers to the use of a digital signature as a second factor to authenticate an external entity.
    private var biometric: BiometricFactorInfo?
    
    public var accountName: String = ""
    
    public var pushToken: String = ""
    
    public var canEnrollBiometric: Bool {
        let isFingerprintEnabled = initializationInfo?.metadata.authenticationMethods.signatureMethods["signature_fingerprint"]?.enabled ?? false
        let isFaceEnabled = initializationInfo?.metadata.authenticationMethods.signatureMethods["signature_face"]?.enabled ?? false
            
        return isFingerprintEnabled || isFaceEnabled
    }
    
    public var canEnrollUserPresence: Bool {
        initializationInfo?.metadata.authenticationMethods.signatureMethods["signature_userPresence"]?.enabled ?? false
    }
       
    /// Initiates the multi-factor method enrollment.
    /// - Parameters:
    ///   - accountName: The account name associated with the service.
    ///   - pushToken: A token that identifies the device to Apple Push Notification Service (APNS).
    ///
    /// Communicate with Apple Push Notification service (APNs) and receive a unique device token that identifies your app.  Refer to [Registering Your App with APNs](https://developer.apple.com/documentation/usernotifications/registering_your_app_with_apns).
    func initiate(with accountName: String, pushToken: String? = nil) async throws {
        // Override the account name assigned with init().
        self.accountName = accountName
        self.pushToken = pushToken ?? ""
        
        var attributes = MFAAttributeInfo.dictionary()
        attributes["accountName"] = self.accountName
        attributes["pushToken"] = self.pushToken
        
        // Update attribuets supported by cloud.
        attributes.removeValue(forKey: "applicationName")
        
        let data: [String: Any] = [
            "code": registrationInfo.code,
            "attributes": attributes
        ]
        
        // Convert body dictionary to Data.
        guard let body = try? JSONSerialization.data(withJSONObject: data, options: []) else {
            throw CloudRegistrationError.dataDecodingFailed(reason: String(localized: "Failed to serialize registration data.", bundle: .module))
        }
        
        let url = URL(string: self.registrationInfo.uri.absoluteString + "?skipTotpEnrollment=true")!
        
        // Construct the request and parsing method.  We decode the metadata, then the token using the TokenInfo in the Authentication module.
        let resource = HTTPResource<(initialization: InitializationInfo, token: TokenInfo)>(.post, url: url, accept: .json, contentType: .json, body: body) { data, response in
            guard let data = data, !data.isEmpty else {
                return Result.failure(CloudRegistrationError.dataInitializationFailed)
            }
            
            do {
                let metadata = try JSONDecoder().decode(InitializationInfo.self, from: data)
                let token = try JSONDecoder().decode(TokenInfo.self, from: data)
                return Result.success((metadata, token))
            }
            catch let decodingError as DecodingError {
                // This block catches specific decoding errors and gives you the details
                return Result.failure(CloudRegistrationError.dataDecodingFailed(reason: decodingError.localizedDescription))
            }
            catch {
                // This catches any other unexpected errors
                return Result.failure(CloudRegistrationError.underlyingError(error: error))
            }
        }
        
        // Perfom the request.
        let result = try await URLSession.shared.dataTask(for: resource)
        self.initializationInfo = result.initialization
        self.token = result.token
    }
    
    // MARK: - User Presence Enrollment
    
    public func enrollUserPresence(savePrivateKey: (SecKeyAddType) throws -> String) async throws {
        let signature: EnrollableSignature = ("signature_userPresence", "userPresence")
        try await performSignatureEnrollment(signature: signature, savePrivateKey: savePrivateKey)
    }
    
    // MARK: - Biometry Enrollment
    
    public func enrollBiometric(savePrivateKey: (SecKeyAddType) throws -> String, context: LAContext? = nil, reason: String?) async throws {
        let context = context ?? LAContext()
        let policy: LAPolicy = .deviceOwnerAuthenticationWithBiometrics
        var error: NSError?

        // Hardware / permission pre-check
        guard context.canEvaluatePolicy(policy, error: &error) else {
            let failure = error?.localizedDescription ?? "Biometry not available."
            throw CloudRegistrationError.biometryFailed(reason: failure)
        }

        let localizedReason = reason ?? String(localized: "Authenticate to enroll", bundle: .module)

        do {
            try await context.evaluatePolicy(policy, localizedReason: localizedReason)
        }
        catch {
            throw CloudRegistrationError.biometryFailed(reason: error.localizedDescription)
        }

        // Determine signature subtype
        let signature: EnrollableSignature
        switch context.biometryType {
        case .faceID:
            signature = ("signature_face", "face")
        case .touchID:
            signature = ("signature_fingerprint", "fingerprint")
        case .none:
            throw CloudRegistrationError.biometryFailed(reason: "No biometry type available.")
        default:
            throw CloudRegistrationError.biometryFailed(reason: "Unsupported biometry type.")
        }

        // Delegate to shared logic
        try await performSignatureEnrollment(signature: signature, savePrivateKey: savePrivateKey)
    }

    // MARK: - Private Methods
    
    private func performSignatureEnrollment(signature: EnrollableSignature, savePrivateKey: (SecKeyAddType) throws -> String) async throws {
        guard let initializationInfo = self.initializationInfo else {
            throw CloudRegistrationError.invalidState
        }
        
        // Validate signature method exists
        guard let method = initializationInfo.metadata.authenticationMethods.signatureMethods[signature.methodKey] else {
            throw CloudRegistrationError.invalidRegistrationData(
                reason: "Signature method '\(signature.subType.camelToTitleCase)' not found."
            )
        }

        guard method.enabled else {
            throw CloudRegistrationError.signatureMethodNotEnabled(
                type: signature.subType.camelToTitleCase
            )
        }

        guard let attributes = method.attributes else {
            throw CloudRegistrationError.invalidRegistrationData(
                reason: "Signature method '\(signature.subType.camelToTitleCase)' has no attributes."
            )
        }

        // Resolve algorithm
        guard let preferredAlgorithm = SigningAlgorithm(from: attributes.algorithm) else {
            throw CloudRegistrationError.invalidAlgorithm(
                reason: "The resolved algorithm '\(attributes.algorithm)' is not valid."
            )
        }

        // Generate key pair
        let privateKey = RSA.Signing.PrivateKey()
        let publicKey = privateKey.publicKey

        // Sign challenge
        let signedChallenge = try sign(initializationInfo.id, with: privateKey, signingAlgorithm: preferredAlgorithm)

        // Store private key
        let keyLabel = try savePrivateKey(.key(value: privateKey.derRepresentation))

        // Perform server enrollment
        try await enroll(for: signature, keyLabel: keyLabel, publicKey: publicKey.x509Representation, signedData: signedChallenge, algorithm: preferredAlgorithm, enrollmentUri: method.enrollmentUri
        )
    }
    
    /// A private helper function to handle the core enrollment logic for all signature factors.
    private func enroll(for signature: EnrollableSignature, keyLabel: String, publicKey: String, signedData: String, algorithm: SigningAlgorithm, enrollmentUri: URL) async throws {
        // 1. Create the parameters for the request body.
        let body = """
        [{
            "subType":"\(signature.subType)",
            "enabled":true,
            "attributes":{
                "signedData":"\(signedData)",
                "publicKey":"\(publicKey)",
                "deviceSecurity":\(signature.subType != "userPresence"),
                "algorithm":"\(algorithm.cloudValue)",
                "additionalData":[{
                    "name":"name",
                    "value":"\(keyLabel)"
                }]
            }
        }]
        """.data(using: .utf8)!
        
        // Safely unwrap the optional token to create the headers dictionary.
        guard let token = self.token else {
            throw MFAServiceError.tokenNotFound
        }
        
        let headers = ["Authorization": token.authorizationHeader]
        
        // 2. Create the resource to execute the request to enroll a signature factor and parse the result.
        let resource = HTTPResource<String>(.post, url: enrollmentUri, accept: .json, contentType: .json, body: body, headers: headers) { data, response in
            guard let data = data, !data.isEmpty else {
                return Result.failure(CloudRegistrationError.dataInitializationFailed)
            }
            
            // Instead of a proxy object to parse this JSON, easier to parse the data to create a new signature factor from a dictionary.
            guard let json = try? JSONSerialization.jsonObject(with: data, options: []) as? [[String: Any]] else {
                return Result.failure(CloudRegistrationError.dataDecodingFailed(reason: String(localized: "Unable to decode JSON from registration response.", bundle: .module)))
            }
            
            // Get the first ID for the signature matching the enrollment type. We'll use this as the identifer for the factor.
            for enrollment in json {
                if let subType = enrollment["subType"] as? String, let id = enrollment["id"] as? String {
                    if subType == signature.subType {
                        return Result.success(id)
                    }
                }
            }
            
            return Result.failure(CloudRegistrationError.enrollmentFailed(reason: "Signature sub-type not found in enrollment response."))
        }
        
        let result = try await URLSession.shared.dataTask(for: resource)
        
        // 3. Assign the result to the appropriate factor property.
        if signature.subType == "face" || signature.subType == "fingerprint" {
            self.biometric = BiometricFactorInfo(id: result, name: keyLabel, algorithm: algorithm)
        }
        else {
            self.userPresence = UserPresenceFactorInfo(id: result, name: keyLabel, algorithm: algorithm)
        }
    }

    public func finalize() async throws -> CloudAuthenticator {
        // Ensure initializationInfo exists before proceeding.
        guard let initializationInfo = self.initializationInfo else {
            throw CloudRegistrationError.invalidState
        }
        
        var attributes = MFAAttributeInfo.dictionary()
        attributes["accountName"] = self.accountName
        attributes["pushToken"] = self.pushToken
        
        // Update attributes supported by cloud.
        attributes.removeValue(forKey: "applicationName")
        
        // Safely unwrap the optional token and its refresh token.
        guard let token = self.token, let refreshToken = token.refreshToken else {
            throw MFAServiceError.tokenNotFound
        }
        
        let headers = ["Authorization": token.authorizationHeader]
        
        let data: [String: Any] = [
            "refreshToken": refreshToken,
            "attributes": attributes
        ]
        
        // Convert body dictionary to Data.
        guard let body = try? JSONSerialization.data(withJSONObject: data, options: []) else {
            throw MFAServiceError.dataDecodingFailed(reason: String(localized: "Failed to convert data to UTF-8 string.", bundle: .module))
        }
        
        // Refresh the token, which sets the authenticator state from ENROLLING to ACTIVE.
        let registrationUri = URL(string: "\(initializationInfo.metadata.registrationUri.absoluteString)?metadataInResponse=false")!
        let transactionUri =  URL(string: initializationInfo.metadata.registrationUri.absoluteString.replacingOccurrences(of: "registration", with: "\(initializationInfo.id)/verifications"))!
                
        let resource = HTTPResource<TokenInfo>(json: .post, url: registrationUri, accept: .json, body: body, headers: headers)
        let result = try await URLSession.shared.dataTask(for: resource)
        
        return CloudAuthenticator(refreshUri: registrationUri,
                                  transactionUri: transactionUri,
                                  theme: initializationInfo.metadata.theme ?? [:],
                                  token: result,
                                  id: initializationInfo.id,
                                  serviceName: initializationInfo.metadata.serviceName,
                                  accountName: self.accountName,
                                  userPresence: self.userPresence,
                                  biometric: self.biometric,
                                  customAttributes: initializationInfo.metadata.customAttributes ?? [:])
    }

    // MARK: - Cloud Registration
    
    struct RegistrationInfo: Decodable {
        /// The endpoint location to complete or initialize an mutli-factor.
        let uri: URL
        
        /// The code which can be used as a  multi-factor registration or login.
        let code: String

        /// The account name associated with the service.
        let accountName: String

        /// The root level JSON structure for decoding.
        private enum CodingKeys: String, CodingKey {
            case code
            case uri = "registrationUri"
            case accountName
        }
    }
    
    // MARK: - Cloud Initialization
    
    /// This structure contains all the necessary information to proceed with multi-factor authentication (MFA) registration, including tokens, metadata for enrollment, and version details.
    struct InitializationInfo: Decodable {
        /// The lifetime in seconds of the access token.
        let expiresIn: Int
        
        /// The resource to enable an authenticator registration. This includes details about available authentication methods and service URIs.
        let metadata: Metadata
        
        /// A unique identifier for the authenticator registration.
        let id: String
        
        /// The access token used for making subsequent API calls.
        let accessToken: String
        
        /// Details about the platform version of the token.
        let version: Version
        
        /// A token that can be used to obtain a new access token once the current one expires.
        let refreshToken: String
    }

    /// Contains information about the authentication registration.
    struct Metadata: Decodable {
        /// The enabled authentication methods for this tenant.
        let authenticationMethods: AuthenticationMethods
        
        /// The location of the registration endpoint.
        let registrationUri: URL
        
        /// The name of the tenant service.
        let serviceName: String
        
        /// Custom theming of the registration.
        let theme: [String: String]?
        
        /// Custom defined attributes. Attribute keys and values are of string type.
        let customAttributes: [String: String]?
    }

    /// Represents version information for the platform.
    struct Version: Decodable {
        /// The interface version number.
        let number: String
        
        /// The product platform identifier.
        let platform: String
    }

    // MARK: - Authentication Method Structures

    /// A custom structure to handle the dynamic keys of the `authenticationMethods` object.

    /// This implementation filters out the "totp" method during decoding.
    struct AuthenticationMethods: Decodable {
        /// Using a dictionary to store the dynamic key-value pairs
        let signatureMethods: [String: SignatureMethod]
        
        init(from decoder: Decoder) throws {
            // Create a keyed container to iterate through the authentication methods.
            let container = try decoder.container(keyedBy: UnknownCodingKeys.self)
            var methods: [String: SignatureMethod] = [:]
            
            for key in container.allKeys {
                // Explicitly skip any key with the value "totp" as requested.
                if key.stringValue != "totp" {
                    let signatureMethod = try container.decode(SignatureMethod.self, forKey: key)
                    methods[key.stringValue] = signatureMethod
                }
            }
            
            self.signatureMethods = methods
        }
    }
}
