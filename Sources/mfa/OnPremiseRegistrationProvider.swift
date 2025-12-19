//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import Foundation
import Authentication
import Core
import CryptoKit
import LocalAuthentication

/// A type that indicates when the on-premise registration fails.
public typealias OnPremiseRegistrationError = MFARegistrationError

/// A mechanism for creating a multi-factor authenticator and associated factor enrollments for IBM Verify Access.
public class OnPremiseRegistrationProvider: MFARegistrationDescriptor {
    public typealias Authenticator = OnPremiseAuthenticator
    
    // MARK: - Initialization
        
    /// Creates the instance with a JSON string value.  The initializer safely decodes the JSON string into an `RegistrationInfo` object.
    ///
    /// - Parameter value: The JSON string value, typically from a QR code.
    /// - Throws: `OnPremiseRegistrationError` if the string cannot be converted to data or if the JSON decoding fails.
    public required init(json value: String) throws {
        // Safely convert the JSON string to Data, throwing an error if it fails.
        guard let data = value.data(using: .utf8) else {
            throw OnPremiseRegistrationError.dataInitializationFailed
        }
        
        let decoder = JSONDecoder()
        
        do {
            // Attempt to decode the data, catching any specific decoding errors.
            let result = try decoder.decode(RegistrationInfo.self, from: data)
            self.registrationInfo = result
            
            if result.ignoreSSLCertificate {
                // Set the URLSession for certificate pinning.
                self.urlSession = URLSession(configuration: .default, delegate: SelfSignedCertificateDelegate(), delegateQueue: nil)
            }
            else {
                self.urlSession = URLSession.shared
            }
        }
        catch {
            // Re-throw the error as a more descriptive one with the original reason.
            throw OnPremiseRegistrationError.dataDecodingFailed(reason: error.localizedDescription)
        }
    }
    
    // MARK: - Properties
    
    /// The default algorithm for enrolling a signature.
    private let defaultAlogirthm = "SHA512withRSA"
    
    /// An object that coordinates a group of related, network data transfer tasks.
    private let urlSession: URLSession
    
    /// A unique identifier to link a mobile application to the on-premise service.
    private var authenticatorId: String = ""
    
    /// The on-premises registration information.
    private let registrationInfo: RegistrationInfo
    
    /// The on-premises metedata to enable authentication initialization.
    private var initializationInfo: InitializationInfo?
    
    /// The access token to authenticate to the on-premises service.
    private var token: TokenInfo?
    
    /// A signature factor refers to the use of a digital signature as a second factor to authenticate an external entity.
    private var userPresence: UserPresenceFactorInfo?
    
    /// A signature factor refers to the use of a digital signature as a second factor to authenticate an external entity.
    private var biometric: BiometricFactorInfo?
    
    public var accountName: String = ""
    
    public var pushToken: String = ""
    
    public var countOfAvailableEnrollments: Int {
        return initializationInfo?.signatureMethods.count ?? 0
    }
    
    public var canEnrollBiometric: Bool {
        initializationInfo?.signatureMethods["fingerprint"]?.enabled ?? false
    }
    
    public var canEnrollUserPresence: Bool {
        initializationInfo?.signatureMethods["user_presence"]?.enabled ?? false
    }
       
    /// Initiates the multi-factor method enrollment.
    /// - Parameters:
    ///   - accountName: The account name associated with the service.
    ///   - pushToken: A token that identifies the device to Apple Push Notification Service (APNS).
    ///   - additionalData: (Optional) A collection of options associated with the registration.
    ///
    ///Communicate with Apple Push Notification service (APNs) and receive a unique device token that identifies your app.  Refer to [Registering Your App with APNs](https://developer.apple.com/documentation/usernotifications/registering_your_app_with_apns).
    internal func initiate(with accountName: String, pushToken: String? = nil, additionalData: [String: Any]? = nil) async throws {
        // Override the account name assigned with init().
        self.accountName = accountName
        self.pushToken = pushToken ?? ""
        
        var attributes = MFAAttributeInfo.dictionary(snakeCaseKey: true)
        attributes["account_name"] = self.accountName
        attributes["push_token"] = self.pushToken
        attributes["tenant_id"] = UUID().uuidString
        
        // If there is additional data, merge with the parameters retaining existing values and only adding 10 additional paramterers
        if let additionalData {
            for (key, value) in additionalData.prefix(10) where attributes[key] == nil {
                attributes[key] = value
            }
        }
        
        // Construct the request and parsing method.  We decode the metadata, then the token using the TokenInfo in the Authentication module.
        let resource = HTTPResource<InitializationInfo>(json: .get, url: self.registrationInfo.uri, accept: .json)
        
        // Perfom the request to get the initialization info.
        do {
            self.initializationInfo = try await self.urlSession.dataTask(for: resource)
        }
        catch let decodingError as DecodingError {
            throw OnPremiseRegistrationError.dataDecodingFailed(reason: decodingError.localizedDescription)
        }
        catch {
            throw OnPremiseRegistrationError.underlyingError(error: error)
        }
        
        // Safely unwrap the initialization info before proceeding.
        guard let info = self.initializationInfo else {
            throw OnPremiseRegistrationError.dataDecodingFailed(reason: String(localized: "Failed to initialize registration data.", bundle: .module))
        }
        
        let token: TokenInfo
        do {
            let oauthProvider = OAuthProvider(clientId: self.registrationInfo.clientId, additionalParameters: attributes, certificateTrust: self.urlSession.delegate)
            token = try await oauthProvider.authorize(issuer: info.tokenUri, authorizationCode: self.registrationInfo.code, scope: ["mmfaAuthn"])
        }
        catch {
            throw OnPremiseRegistrationError.dataDecodingFailed(reason: error.localizedDescription)
        }
        
        // Check for the authenticator_id from the token additionalData.
        guard let authenticatorId = token.additionalData["authenticator_id"] as? String else {
            throw OnPremiseRegistrationError.missingAuthenticatorIdentifier
        }
        
        self.authenticatorId = authenticatorId
        self.token = token
    }
    
    // MARK: - User Presence Enrollment

    public func enrollUserPresence(savePrivateKey: (SecKeyAddType) throws -> String) async throws {
        let signature = (methodKey: "user_presence", subType: "userPresence")
        try await performSignatureEnrollment(signature: signature, savePrivateKey: savePrivateKey)
    }
    
    // MARK: - Biometry Enrollment

    public func enrollBiometric(savePrivateKey: (SecKeyAddType) throws -> String, context: LAContext? = nil, reason: String?) async throws {
        let context = context ?? LAContext()
        let policy: LAPolicy = .deviceOwnerAuthenticationWithBiometrics
        var error: NSError?

        // Hardware / permission pre-check
        guard context.canEvaluatePolicy(policy, error: &error) else {
            let failureReason = error?.localizedDescription ?? "Biometry not available."
            throw OnPremiseRegistrationError.biometryFailed(reason: failureReason)
        }

        let localizedReason = reason ?? String(localized: "Authenticate to enroll", bundle: .module)
        
        // Perform the async evaluation and map errors to your domain error
        do {
            try await context.evaluatePolicy(policy, localizedReason: localizedReason)
        }
        catch {
            throw OnPremiseRegistrationError.biometryFailed(reason: error.localizedDescription)
        }
        
        // Determine signature subtype
        let signature: EnrollableSignature
        switch context.biometryType {
        case .touchID, .faceID:
            signature = ("fingerprint", "fingerprint")
        case .none:
            throw OnPremiseRegistrationError.biometryFailed(reason: "No biometry type available after authentication.")
        default:
            throw OnPremiseRegistrationError.biometryFailed(reason: "Unsupported biometry type")
        }

        // Delegate to shared logic
        try await performSignatureEnrollment(signature: signature, savePrivateKey: savePrivateKey)
    }
    
    // MARK: - Private Methods
    
    private func performSignatureEnrollment(signature: EnrollableSignature, savePrivateKey: (SecKeyAddType) throws -> String) async throws {
        guard let initializationInfo = self.initializationInfo else {
            throw OnPremiseRegistrationError.invalidState
        }

        // Validate signature method exists
        guard let method = initializationInfo.signatureMethods[signature.methodKey] else {
            throw OnPremiseRegistrationError.invalidRegistrationData(reason: String(localized: "Signature method '\(signature.subType.camelToTitleCase)' not found.", bundle: .module))
        }

        guard method.enabled else {
            throw OnPremiseRegistrationError.signatureMethodNotEnabled(
                type: signature.subType.camelToTitleCase
            )
        }

        guard let attributes = method.attributes else {
            throw OnPremiseRegistrationError.invalidRegistrationData(
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

        // Store private key
        let keyLabel = try savePrivateKey(.key(value: privateKey.derRepresentation))

        // Perform server enrollment
        try await enroll(for: signature, keyLabel: keyLabel, publicKey: publicKey.x509Representation, algorithm: preferredAlgorithm, enrollmentUri: method.enrollmentUri)
    }
    
    /// A private helper function to handle the core enrollment logic for all signature factors.
    private func enroll(for signature: EnrollableSignature, keyLabel: String, publicKey: String, algorithm: SigningAlgorithm, enrollmentUri: URL) async throws {
        // 1. Create the parameters for the request body.
        let path = "urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Authenticator:\(signature.subType)Methods"
           
        // Append SCIM specific components as a query string.
        guard let url = URL(string: "\(enrollmentUri.absoluteString)?attributes=\(path)") else {
            throw URLError(.badURL)
        }
        
        let body = """
        {
            "schemas": [
                "urn:ietf:params:scim:api:messages:2.0:PatchOp"
            ],
            "Operations": [{
                "op": "add",
                "path": "\(path)",
                "value": [{
                    "enabled": true,
                    "keyHandle": "\(keyLabel)",
                    "algorithm": "\(algorithm.onPremiseValue)",
                    "publicKey": "\(publicKey)"
                }]
            }]
        }
        """.data(using: .utf8)!

        // Safely unwrap the optional token to create the headers dictionary.
        guard let token = self.token else {
            throw MFAServiceError.tokenNotFound
        }
         
        let headers = ["Authorization": token.authorizationHeader]
        
        // 7. Create the resource to execute the request to enroll a signature factor and parse the result.
        let resource = HTTPResource<String>(.patch, url: url, accept: .json, contentType: .json, body: body, headers: headers) { data, response in
            guard let _ = data else {
                return Result.failure(OnPremiseRegistrationError.dataInitializationFailed)
            }
            
            return Result.success(UUID().uuidString)
        }
        
        let result = try await self.urlSession.dataTask(for: resource)
        
        // 8. Assign the result to the appropriate factor property.
        if signature.subType == "fingerprint" {
            self.biometric = BiometricFactorInfo(id: result, name: keyLabel, algorithm: algorithm)
        }
        else {
            self.userPresence = UserPresenceFactorInfo(id: result, name: keyLabel, algorithm: algorithm)
        }
    }

    public func finalize() async throws -> OnPremiseAuthenticator {
        // Ensure initializationInfo exists before proceeding.
        guard let initializationInfo = self.initializationInfo else {
            throw OnPremiseRegistrationError.invalidState
        }
        
        // Safely unwrap the optional token and its refresh token.
        guard let token = self.token else {
            throw MFAServiceError.tokenNotFound
        }
        
        return OnPremiseAuthenticator(refreshUri: initializationInfo.registrationUri,
                                      transactionUri: initializationInfo.transactionUri,
                                      theme: initializationInfo.metadata.theme ?? [:] ,
                                      token: token,
                                      id: self.authenticatorId,
                                      serviceName: initializationInfo.metadata.serviceName,
                                      accountName: self.accountName,
                                      userPresence: self.userPresence,
                                      biometric: self.biometric,
                                      qrloginUri: initializationInfo.qrloginUri,
                                      ignoreSSLCertificate: self.registrationInfo.ignoreSSLCertificate,
                                      clientId: self.registrationInfo.clientId)
    }
    
    // MARK: - On-Premise Registration
    
    struct RegistrationInfo: Codable {
        /// A unique registration code.
        let code: String
        
        /// A raw options string containing configuration flags (e.g., "ignoreSslCerts=false").
        let options: String
        
        /// A URL pointing to user details.
        let uri: URL
        
        /// The version number of the registration payload.
        let version: Int
        
        /// The client identifier (e.g., "IBMVerify").
        let clientId: String

        /// Maps JSON keys to Swift property names where they differ.
        enum CodingKeys: String, CodingKey {
            case code
            case options
            case uri = "details_url" // Maps "details_url" from JSON to "detailsURL"
            case version
            case clientId = "client_id"     // Maps "client_id" from JSON to "clientID"
        }

        /// A computed property that parses the `options` string and returns a Boolean indicating whether SSL certificate validation should be ignored.
        ///
        /// When this flag is `true` a  [URLSessionDelegate](https://developer.apple.com/documentation/foundation/urlsessiondelegate/1409308-urlsession) should be assigned to the `URLSession` to validate authentication challenges. For example certificate pinning.
        /// - Returns: `true` if `ignoreSslCerts=true` is present in the options string; otherwise `false`.
        var ignoreSSLCertificate: Bool {
            // Split the options string into key-value pairs using commas
            let pairs = options.split(separator: ",").map { $0.split(separator: "=") }

            // Iterate through each key-value pair
            for pair in pairs {
                // Ensure the pair contains exactly two elements: key and value
                if pair.count == 2 {
                    let key = pair[0].trimmingCharacters(in: .whitespaces)
                    let value = pair[1].trimmingCharacters(in: .whitespaces).lowercased()

                    // Check if the key is "ignoreSslCerts" and return true if the value is "true"
                    if key == "ignoreSslCerts" {
                        return value == "true"
                    }
                }
            }

            // Default to false if the key is not found or improperly formatted
            return false
        }
    }

    // MARK: - On-Premise Initialization
    
    ///This structure contains all the necessary information to proceed with multi-factor authentication (MFA) registration, including tokens, metadata for enrollment, and version details.
    struct InitializationInfo: Codable {
        /// Endpoint for authentication transaction queries.
        let transactionUri: URL
        
        /// Metadata containing service-related information.
        let metadata: Metadata
        
        /// List of supported discovery mechanisms (e.g., fingerprint, user_presence).
        let discoveryMechanisms: [String]
        
        /// Endpoint for enrollment operations.
        let registrationUri: URL
        
        /// The QR code login location endpoint URL
        /// - remark: This value is retrieved from `qrlogin_endpoint`.  If the value is missing, an attempt is made to retrieved the `qrlogin_endpoint` value from the on-premise metadata.json file.
        ///
        /// **metadata.json**
        /// ```
        /// { "qrlogin_endpoint" : "uri" }
        /// ```
        ///
        /// - note: If not value is available QR login is not supported.
        let qrloginUri: URL?
        
        /// Version string of the configuration.
        let version: String
        
        /// OAuth token endpoint.
        let tokenUri: URL
        
        /// The resource to enable an authenticator registration. This includes details about available authentication methods and service URIs.
        var signatureMethods: [String: SignatureMethod] {
            [
                "fingerprint": "urn:ibm:security:authentication:asf:mechanism:mobile_user_approval:fingerprint",
                "user_presence": "urn:ibm:security:authentication:asf:mechanism:mobile_user_approval:user_presence"
            ]
            .filter { _, urn in discoveryMechanisms.contains(urn) }
            .mapValues { _ in
                SignatureMethod(
                    enrollmentUri: registrationUri,
                    attributes: SignatureAttributes(
                        supportedAlgorithms: ["SHA512withRSA"],
                        algorithm: "SHA512withRSA"
                    ),
                    enabled: true
                )
            }
        }

        /// Maps JSON keys to Swift property names.
        enum CodingKeys: String, CodingKey {
            case transactionUri = "authntrxn_endpoint"
            case metadata
            case discoveryMechanisms = "discovery_mechanisms"
            case registrationUri = "enrollment_endpoint"
            case qrloginUri = "qrlogin_endpoint"
            case version
            case tokenUri = "token_endpoint"
        }
    }

    /// Represents metadata information embedded in the initialization payload.
    struct Metadata: Codable {
        /// Name of the service (e.g., "ISVA Service").
        let serviceName: String
        
        /// A custom color scheme that can be applied to app elements.  For example, buttons, background-color, text color.
        let theme: [String: String]?

        /// Maps JSON key to Swift property name.
        enum CodingKeys: String, CodingKey {
            case serviceName = "service_name"
            case theme
        }
    }
}
