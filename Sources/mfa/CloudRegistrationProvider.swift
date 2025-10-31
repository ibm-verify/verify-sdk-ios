//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import Foundation
import Authentication
import Core
import CryptoKit

/// A type that indicates when the cloud registration fails.
public typealias CloudRegistrationError = MFARegistrationError

/// A mechanism for creating a multi-factor authenticator and associated factor enrollments for IBM Verify.
public class CloudRegistrationProvider: MFARegistrationDescriptor {
    public typealias Authenticator = CloudAuthenticator
    
    /// Initiate an authenticator registration for IBM Verify instances or custom mobile authenticators.
    /// - Parameters:
    ///   - initiateUri: The endpoint location to initiate an mutli-factor device registration.
    ///   - accessToken: The authenticated user token.
    ///   - clientId: The unique identifier of the authenticator client to be associated with the registration.
    ///   - accountName: The account name associated with the service.
    /// - Returns: A JSON structure representing the registration initiation.
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
        // Create the request headers.
        let headers = ["Authorization": "Bearer \(accessToken)"]
        
        // Construct the request body and parsing method.
        let body = """
        {
            "clientId": "\(clientId)",
            "accountName": "\(accountName)"
        }
        """.data(using: .utf8)!
        
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
                return Result.failure(CloudRegistrationError.failedToParse)
            }
            
            return Result.success(value)
        }
        
        return try await URLSession.shared.dataTask(for: resource)
    }
    
    /// Creates the instance with a JSON string value.
    /// - Parameters:
    ///   - value: The JSON value typically obtained from a QR code.
    public required init(json value: String) throws {
        let decoder = JSONDecoder()
        guard let result = try? decoder.decode(InitializationInfo.self, from: value.data(using: .utf8)!) else {
            throw MFARegistrationError.failedToParse
        }
        
        self.pushToken = ""
        self.accountName = result.accountName
        self.initializationInfo = result
    }
    
    /// The cloud initialization information.
    private let initializationInfo: InitializationInfo
    
    /// The cloud metedata to enable authentication registration.
    private var metadata: Metadata!
    
    /// The access token to authenticate to the cloud service.
    private var token: TokenInfo!
    
    /// The array of factors that have been enrolled.
    private var factors: [FactorType] = [FactorType]()
    
    /// The current factor that is being enrolled.
    private var currentFactor: SignatureEnrollableFactor!
    
    public var accountName: String
    
    public var pushToken: String
    
    public var countOfAvailableEnrollments: Int {
        return metadata.availableFactors.count
    }
    
    public var skipTotpEnrollment: Bool = true
       
    /// Initiates the multi-factor method enrollment.
    /// - Parameters:
    ///   - accountName: The account name associated with the service.
    ///   - skipTotpEnrollment: A Boolean value that when set to `true` the TOTP authentication method enrollment attempt will be skipped.
    ///   - pushToken: A token that identifies the device to Apple Push Notification Service (APNS).
    ///
    /// Communicate with Apple Push Notification service (APNs) and receive a unique device token that identifies your app.  Refer to [Registering Your App with APNs](https://developer.apple.com/documentation/usernotifications/registering_your_app_with_apns).
    internal func initiate(with accountName: String, skipTotpEnrollment: Bool = true, pushToken: String? = nil) async throws {
        // Override the account name assigned with init().
        self.accountName = accountName
        self.pushToken = pushToken ?? ""
        
        var attributes = MFAAttributeInfo.dictionary()
        attributes["accountName"] = self.accountName
        attributes["pushToken"] = self.pushToken
        
        // Update attribuets supported by cloud.
        attributes.removeValue(forKey: "applicationName")
        
        let data: [String: Any] = [
            "code": initializationInfo.code,
            "attributes": attributes
        ]
        
        // Convert body dictionary to Data.
        guard let body = try? JSONSerialization.data(withJSONObject: data, options: []) else {
            throw CloudRegistrationError.failedToParse
        }
        
        let url = URL(string: self.initializationInfo.uri.absoluteString + "?skipTotpEnrollment=\(skipTotpEnrollment)")!
        
        // Construct the request and parsing method.  We decode the metadata, then the token using the TokenInfo in the Authentication module.
        let resource = HTTPResource<(metadata: Metadata, token: TokenInfo)>(.post, url: url, accept: .json, contentType: .json, body: body) { data, response in
            guard let data = data, !data.isEmpty else {
                return Result.failure(CloudRegistrationError.dataInitializationFailed)
            }
            
            guard let metadata = try? JSONDecoder().decode(Metadata.self, from: data), let token = try? JSONDecoder().decode(TokenInfo.self, from: data) else {
                return Result.failure(CloudRegistrationError.failedToParse)
            }
            return Result.success((metadata, token))
        }
        
        // Perfom the request.
        let result = try await URLSession.shared.dataTask(for: resource)
        self.metadata = result.metadata
        self.token = result.token
        
        // Check if TOTP got auto enrolled, if so remove it and append it to factors.
        if let factor = self.metadata.availableFactors.first(where: { $0 is CloudTOTPEnrollableFactor }) as? CloudTOTPEnrollableFactor {
            if !skipTotpEnrollment {
                // Convert the enrollable factor.
                self.factors = [
                    .totp(TOTPFactorInfo(with: factor.secret, digits: factor.digits, algorithm: HashAlgorithmType(rawValue: factor.algorithm) ?? .sha1, period: factor.period))
                ]
            }
            
            // Remove the factor from being called from nextEnrollment
            self.metadata.availableFactors.removeAll(where: { $0 is CloudTOTPEnrollableFactor })
        }
        
        // Check if both face and fingerprint factors are available. If so, then determine the device biometry sensor and remove the unsupported factor.
        if self.metadata.availableFactors.contains(where: { $0.type == .fingerprint }) && MFAAttributeInfo.hasTouchID {
            self.metadata.availableFactors.removeAll(where: { $0.type == .face })
        }
        
        if self.metadata.availableFactors.contains(where: { $0.type == .face }) && MFAAttributeInfo.hasFaceID {
            self.metadata.availableFactors.removeAll(where: { $0.type == .fingerprint })
        }
    }
              
    public func nextEnrollment() async -> EnrollableSignature? {
        // Get the next enrollable factor from metadata.
        guard let factor = self.metadata.availableFactors.first as? SignatureEnrollableFactor else {
            return nil
        }
        
        defer {
            self.currentFactor = factor
            
            // Remove the factor from being called from nextEnrollment
            self.metadata.availableFactors.removeAll(where: { $0.type == factor.type })
        }
        
        let algorithm = HashAlgorithmType.init(rawValue: factor.algorithm)!
        
        // Determine if the factor requires biometry.
        let biometricAuthentication = factor.type == EnrollableType.userPresence ? false : true
       
        return EnrollableSignature(biometricAuthentication: biometricAuthentication, algorithm: algorithm, dataToSign: self.metadata.id)
    }
    
    public func enroll() async throws {
        // The name of the Keychain item is made up of the authenticator identifier and the factor type, consistent with existing Keychain entries.
        let name = "\(self.metadata.id).\(self.currentFactor.type.rawValue)"
        let publicKey = try generateKeys(name: name, biometricAuthentication: self.currentFactor.type == .face || self.currentFactor.type == .fingerprint)
        let signedData = try sign(name: name, algorithm: self.currentFactor.algorithm, dataToSign: self.metadata.id)
        
        try await enroll(with: name, publicKey: publicKey, signedData: signedData)
    }

    public func enroll(with name: String, publicKey: String, signedData: String) async throws {
        guard let algorithm = HashAlgorithmType.init(rawValue: self.currentFactor.algorithm) else {
            throw HashAlgorithmError.invalidHash
        }
        
        // Create the parameters for the request body.
        let body = """
            [{
                "subType":"\(self.currentFactor.type.rawValue)",
                "enabled":true,
                "attributes":{
                    "signedData":"\(signedData)",
                    "publicKey":"\(publicKey)",
                    "deviceSecurity":\(self.currentFactor.type == .face || self.currentFactor.type == .fingerprint),
                    "algorithm":"\(self.currentFactor.algorithm)",
                    "additionalData":[{
                        "name":"name",
                        "value":"\(name)"
                    }]
                }
            }]
        """.data(using: .utf8)!
        
        // Create the resource to execute the request to enroll a signature factor and parse the result.
        let resource = HTTPResource<UUID>(.post, url: self.currentFactor.uri, accept: .json, contentType: .json, body: body, headers: ["Authorization": self.token.authorizationHeader]) { data, response in
            guard let data = data, !data.isEmpty else {
                return Result.failure(CloudRegistrationError.dataInitializationFailed)
            }
            
            // Instead of a proxy object to parse this JSON, easier to parse the data to create a new signature factor from a dictionary.
            guard let json = try? JSONSerialization.jsonObject(with: data, options: []) as? [[String: Any]] else {
                return Result.failure(CloudRegistrationError.failedToParse)
            }
            
            // Get the first ID for the signature matching the enrollment type.  We'll use this as the identifer for the factor.
            for enrollment in json {
                if let subType = enrollment["subType"] as? String, let type = EnrollableType(rawValue: subType), let id = enrollment["id"] as? String, let uuid = UUID(uuidString: id) {
                    
                    if type == self.currentFactor.type {
                        return Result.success(uuid)
                    }
                }
            }
            
            return Result.failure(CloudRegistrationError.enrollmentFailed)
        }
        
        
        let result = try await URLSession.shared.dataTask(for: resource)
        
        if self.currentFactor.type == .face {
            self.factors.append(.face(FaceFactorInfo(id: result, name: name, algorithm: algorithm)))
        }
        else if self.currentFactor.type == .fingerprint {
            self.factors.append(.fingerprint(FingerprintFactorInfo(id: result, name: name, algorithm: algorithm)))
        }
        else {
            self.factors.append(.userPresence(UserPresenceFactorInfo(id: result, name: name, algorithm: algorithm)))
        }
    }

    public func finalize() async throws -> CloudAuthenticator {
        var attributes = MFAAttributeInfo.dictionary()
        attributes["accountName"] = self.accountName
        attributes["pushToken"] = self.pushToken
        
        // Update attribuets supported by cloud.
        attributes.removeValue(forKey: "applicationName")
        
        let data: [String: Any] = [
            "refreshToken": self.token.refreshToken!,
            "attributes": attributes
        ]
        
        // Convert body dictionary to Data.
        guard let body = try? JSONSerialization.data(withJSONObject: data, options: []) else {
            throw MFAServiceError.serializationFailed
        }
        
        // Refresh the token, which sets the authenticator state from ENROLLING to ACTIVE.
        let registrationUri = URL(string: self.metadata.registrationUri.absoluteString + "?metadataInResponse=false")!
        let resource = HTTPResource<TokenInfo>(json: .post, url: registrationUri, accept: .json, body: body, headers: ["Authorization": self.token.authorizationHeader])

        
        let result = try await URLSession.shared.dataTask(for: resource)
        
        return CloudAuthenticator(refreshUri: self.metadata.registrationUri,
                                  transactionUri: self.metadata.transactionUri,
                                  theme: self.metadata.theme,
                                  token: result,
                                  id: self.metadata.id,
                                  serviceName: self.metadata.serviceName,
                                  accountName: self.accountName,
                                  allowedFactors: self.factors,
                                  customAttributes: self.metadata.custom)
    }

    // MARK: - Cloud initialization
    internal struct InitializationInfo: Decodable {
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
    
    // MARK: - Cloud metadata
    
    /// The metadata associated with the service.
    internal struct Metadata: Decodable {
        /// An identifier generated by the service to uniquely identify an authenticator.
        let id: String
        
        /// The domain of the site or app.
        let serviceName: String
        
        /// The registration location endpoint URL.
        let registrationUri: URL

        /// The transaction location endpoint URL.
        let transactionUri: URL

        /// The collection of available enrollment factors.
        var availableFactors: [EnrollableFactor] = []

        /// A custom color scheme that can be applied to app elements.  For example, buttons, background-color, text color.
        let theme: [String: String]

        /// Used to define features that can be applied to an app.
        let features: [String]
        
        /// Used to define custom property or settings that can be applied to an app.
        let custom: [String: String]
        
    
        // MARK: Enums

        /// The root level JSON structure for decoding.
        private enum CodingKeys: String, CodingKey {
            case id = "id"
            case metadata
        }
        
        /// The `metadata` decoding structure.
        private enum MetadataCodingKeys: String, CodingKey {
            case serviceName
            case registrationUri
            case features = "featureFlags"
            case theme = "themeAttributes"
            case custom = "customAttributes"
            case authenticationMethods = "authenticationMethods"
        }
        
        /// The "customAttributes" decoding structure based off `CodingKeys`.
        private enum CustomAttributesCodingKeys: String, CodingKey {
            case theme
        }

        /// The "authenticationMethods" decoding structure based off `CodingKeys`.
        private enum AuthenticationMethodsCodingKeys: String, CodingKey {
            case totp
            case face = "signature_face"
            case fingerprint = "signature_fingerprint"
            case userpresence = "signature_userPresence"
        }
        
        /// The "totp" decoding structure based off `CodingKeys` for `AuthenticationMethodsCodingKeys`
        private enum TOTPCodingKeys: String, CodingKey {
            case enabled
            case enrollmentUri
            case id
            case attributes
        }

        /// The "signature_fingerprint", "signature_face" and "signature_userPresence"  decoding structure based off `CodingKeys` for `AuthenticationMethodsCodingKeys`.
        private enum SignatureCodingKeys: String, CodingKey {
            case enabled
            case enrollmentUri
            case attributes
        }
        
        ///  The "attribute" decoding structure based off `CodingKeys` for `SignatureCodingKeys`
        private enum AttributesCodingKeys: String, CodingKey {
            case algorithm
            case secret
            case digits
            case period
        }
        
        /// Creates a new instance by decoding from the given decoder
        /// - parameter decoder: The decoder to read data from.
        internal init(from decoder: Decoder) throws {
            let rootContainer = try decoder.container(keyedBy: CodingKeys.self)
            
            self.id = try rootContainer.decode(String.self, forKey: .id)
           
            // Metadata Keys
            let metadataContainer = try rootContainer.nestedContainer(keyedBy: MetadataCodingKeys.self, forKey: .metadata)
            self.serviceName = try metadataContainer.decode(String.self, forKey: .serviceName)
            self.registrationUri = try metadataContainer.decode(URL.self, forKey: .registrationUri)
            self.transactionUri = URL(string: registrationUri.absoluteString.replacingOccurrences(of: "registration", with: "\(self.id)/verifications"))!
            self.features = try metadataContainer.decodeIfPresent([String].self, forKey: .features) ?? []
            self.custom = try metadataContainer.decodeIfPresent([String: String].self, forKey: .custom) ?? [:]
            self.theme = try metadataContainer.decodeIfPresent([String: String].self, forKey: .theme) ?? [:]
            
            // Get the values to assign to signature and one-time passcode authentication factors.
            var availableFactors: [EnrollableFactor] = []
            
            if metadataContainer.contains(.authenticationMethods) {
                let authenticationContainer = try metadataContainer.nestedContainer(keyedBy: AuthenticationMethodsCodingKeys.self, forKey: .authenticationMethods)
                
                // Check if userpresence signature is present and enabled.
                if authenticationContainer.contains(.userpresence) {
                    let container = try authenticationContainer.nestedContainer(keyedBy: SignatureCodingKeys.self, forKey: .userpresence)
                    
                    if let factor = try? createSignatureFactor(container, type: .userPresence) {
                        availableFactors.append(factor)
                    }
                }
                
                // Check if fingerprint signature is present and enabled.
                if authenticationContainer.contains(.fingerprint) {
                    let container = try authenticationContainer.nestedContainer(keyedBy: SignatureCodingKeys.self, forKey: .fingerprint)
                    
                    if let factor = try? createSignatureFactor(container, type: .fingerprint) {
                        availableFactors.append(factor)
                    }
                }
                
                // Check if face signature is present and enabled.
                if authenticationContainer.contains(.face) {
                    let container = try authenticationContainer.nestedContainer(keyedBy: SignatureCodingKeys.self, forKey: .face)
                    
                    if let factor = try? createSignatureFactor(container, type: .face) {
                        availableFactors.append(factor)
                    }
                }
                
                // Check if totp is present, enabled and contains attributes. Where attributes don't exist, it means the user has an existing TOTP enrollment.
                if authenticationContainer.contains(.totp) {
                    let totp = try authenticationContainer.nestedContainer(keyedBy: TOTPCodingKeys.self, forKey: .totp)
                
                    if totp.contains(.attributes) {
                        if try totp.decode(Bool.self, forKey: .enabled) {
                            let enrollmentUri = try totp.decode(URL.self, forKey: .enrollmentUri)
                            let id = try totp.decode(String.self, forKey: .id)
                            let attributesContainer = try totp.nestedContainer(keyedBy: AttributesCodingKeys.self, forKey: .attributes)
                            let algorithm = try attributesContainer.decode(String.self, forKey: .algorithm )
                            let period = try attributesContainer.decode(Int.self, forKey: .period)
                            let digits = try attributesContainer.decode(Int.self, forKey: .digits)
                            let secret = try attributesContainer.decode(String.self, forKey: .secret)
                           
                            availableFactors.append(CloudTOTPEnrollableFactor(uri: enrollmentUri, id: id, algorithm: algorithm, secret: secret, digits: digits, period: period))
                        }
                    }
                }
            }
            
            self.availableFactors = availableFactors
        }
        
        /// Create a signature enrollment factor.
        /// - Parameters:
        ///    - container: A concrete container that provides a view into a decoder’s storage, making the encoded properties of a decodable type accessible by keys.
        ///    - type: The `FactorType` value for the signature.
        /// - Returns: An instance of `EnrollmentFactor` otherwise, `nil`.
        private func createSignatureFactor(_ container: KeyedDecodingContainer<CloudRegistrationProvider.Metadata.SignatureCodingKeys>, type: EnrollableType) throws -> SignatureEnrollableFactor? {
            if try container.decode(Bool.self, forKey: .enabled) {
                let uri = try container.decode(URL.self, forKey: .enrollmentUri)
                let attributesContainer = try container.nestedContainer(keyedBy: AttributesCodingKeys.self, forKey: .attributes)
                let algorithm = try attributesContainer.decode(String.self, forKey: .algorithm)
                
                return SignatureEnrollableFactor(uri: uri, type: type, algorithm: algorithm)
            }
            
            return nil
        }
    }
}
