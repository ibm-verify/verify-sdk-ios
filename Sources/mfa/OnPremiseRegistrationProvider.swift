//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import Foundation
import Authentication
import Core
import CryptoKit

/// A type that indicates when the on-premise registration fails.
public typealias OnPremiseRegistrationError = MFARegistrationError

/// A mechanism for creating a multi-factor authenticator and associated factor enrollments for IBM Verify Access.
public class OnPremiseRegistrationProvider: MFARegistrationDescriptor {
    public typealias Authenticator = OnPremiseAuthenticator
    
    /// Creates the instance with a JSON string value.
    /// - Parameters:
    ///   - value: The JSON value typically obtained from a QR code.
    public required init(json value: String) throws {
        let decoder = JSONDecoder()
        guard let result = try? decoder.decode(InitializationInfo.self, from: value.data(using: .utf8)!) else {
            throw MFARegistrationError.failedToParse
        }
        
        self.authenitcatorId = ""
        self.pushToken = ""
        self.accountName = ""
        self.initializationInfo = result
        
        if result.ignoreSSLCertificate {
            // Set the URLSession for certificate pinning.
            self.urlSession = URLSession(configuration: .default, delegate: SelfSignedCertificateDelegate(), delegateQueue: nil)
        }
        else {
            self.urlSession = URLSession.shared
        }
    }
    
    /// An object that coordinates a group of related, network data transfer tasks.
    private let urlSession: URLSession
    
    /// The on-premise initialization information.
    private var initializationInfo: InitializationInfo
    
    /// The on-premise metedata to enable authentication registration.
    private var metadata: Metadata!
    
    /// The access token to authenticate to the on-premise service.
    private var token: TokenInfo!
    
    /// The array of factors that have been enrolled.
    private var factors: [FactorType] = [FactorType]()
    
    /// The current factor that is being enrolled.
    private var currentFactor: SignatureEnrollableFactor!
    
    /// The `UUID` identifier generated in IBM Verify Access.
    private var authenitcatorId: String
    
    public var accountName: String
    
    public var pushToken: String
    
    public var countOfAvailableEnrollments: Int {
        return metadata.availableFactors.count
    }
       
    /// Initiates the multi-factor method enrollment.
    /// - Parameters:
    ///   - accountName: The account name associated with the service.
    ///   - skipTotpEnrollment: A Boolean value that when set to `true` the TOTP authentication method enrollment attempt will be skipped.
    ///   - pushToken: A token that identifies the device to Apple Push Notification Service (APNS).
    ///   - additionalData: (Optional) A collection of options associated with the registration.
    ///
    ///Communicate with Apple Push Notification service (APNs) and receive a unique device token that identifies your app.  Refer to [Registering Your App with APNs](https://developer.apple.com/documentation/usernotifications/registering_your_app_with_apns).
    internal func initiate(with accountName: String, skipTotpEnrollment: Bool = true, pushToken: String? = nil, additionalData: [String: Any]? = nil) async throws {
        // Override the account name assigned with init().
        self.accountName = accountName
        self.pushToken = pushToken ?? ""
        
        var parameters = MFAAttributeInfo.dictionary(snakeCaseKey: true)
        parameters["account_name"] = accountName
        parameters["push_token"] = self.pushToken
        parameters["tenant_id"] = UUID().uuidString
        
        // If there is additional data, merge with the parameters retaining existing values and only adding 10 additional paramterers
        if let additionalData = additionalData {
            var index = 1
            additionalData.forEach {
                if parameters.index(forKey: $0.key) == nil && index <= 10 {
                    parameters.updateValue($0.value, forKey: $0.key)
                    index += 1
                }
            }
        }
        
        // Construct the request and parsing method.  We decode the metadata, then the token using the TokenInfo in the Authentication module.
        let resource = HTTPResource<Metadata>(json: .get, url: self.initializationInfo.uri, accept: .json)
        
        // Perfom the request.
        self.metadata = try await self.urlSession.dataTask(for: resource)
            
        let oauthProvider = OAuthProvider(clientId: self.initializationInfo.clientId, additionalParameters: parameters, certificateTrust: self.urlSession.delegate)
        self.token = try await oauthProvider.authorize(issuer: metadata.registrationUri, authorizationCode: self.initializationInfo.code, scope: ["mmfaAuthn"])
        
        // Check for the authenticator_id from the token additionalData.
        guard let authenitcatorId = token.additionalData["authenticator_id"] as? String else {
            throw OnPremiseRegistrationError.missingAuthenticatorIdentifier
        }
        
        self.authenitcatorId = authenitcatorId
        
        // Complete with error when no factors are available for enrollment.
        if self.metadata.availableFactors.count == 0 {
            throw OnPremiseRegistrationError.noEnrollableFactors
        }
        
        // Automatically enroll for TOTP is available.
        if let factor = self.metadata.availableFactors.first(where: { $0 is OnPremiseTOTPEnrollableFactor }) as? OnPremiseTOTPEnrollableFactor {
            if !skipTotpEnrollment {
                let totpResource = HTTPResource<TOTPFactorInfo>(url: factor.uri, headers: ["Authorization": self.token.authorizationHeader]) { data, response in
                    
                    guard let data = data, !data.isEmpty else {
                        return Result.failure(OnPremiseRegistrationError.dataInitializationFailed)
                    }
                    
                    // Instead of a proxy object to parse this JSON, easier to construct a new TOTPFactorInfo from a dictionary.
                    guard let json = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: String] else {
                        return Result.failure(OnPremiseRegistrationError.failedToParse)
                    }
                    
                    guard let secret = json["secretKey"], let digits = Int(json["digits"]!), let algorithm = json["algorithm"], let period = Int(json["period"]!) else {
                        return Result.failure(OnPremiseRegistrationError.enrollmentFailed)
                    }
                    
                    return Result.success(TOTPFactorInfo(with: secret, digits: digits, algorithm: HashAlgorithmType(rawValue: algorithm) ?? .sha1, period: period))
                }
                
                let totp = try await self.urlSession.dataTask(for: totpResource)
                self.factors.append(.totp(totp))
            }
            
            // Remove the factor from being called from nextEnrollment
            self.metadata.availableFactors.removeAll(where: { $0 is OnPremiseTOTPEnrollableFactor })
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
       
        return EnrollableSignature(biometricAuthentication: biometricAuthentication, algorithm: algorithm, dataToSign: self.authenitcatorId)
    }
    
    public func enroll() async throws {
        // The name of the Keychain item is made up of the authenticator identifier and the factor type, consistent with existing Keychain entries.
        let name = "\(self.authenitcatorId).\(self.currentFactor.type.rawValue)"
        let publicKey = try generateKeys(name: name, biometricAuthentication: self.currentFactor.type == .face || self.currentFactor.type == .fingerprint)
        
        // Although on-premise enrollments don't use signed data, we invoke it all the same for biometry verification where the private key is protected in the Keychain.
        let signedData = try sign(name: name, algorithm: self.currentFactor.algorithm, dataToSign: self.authenitcatorId)
        
        try await enroll(with: name, publicKey: publicKey, signedData: signedData)
    }

    public func enroll(with name: String, publicKey: String, signedData: String) async throws {
        let algorithm = HashAlgorithmType.init(rawValue: self.currentFactor.algorithm)!
        let path = "urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Authenticator:\(self.currentFactor.type.rawValue)Methods"
        let id = UUID()
        let keyHandle = "\(id.uuidString).\(self.currentFactor.type.rawValue)"
         
        // Append SCIM specific components as a query string.
        guard let url = URL(string: "\(self.currentFactor.uri.absoluteString)?attributes=\(path)") else {
            throw URLError(.badURL)
        }
        
        // Create the parameters for the request body.
        let body = """
            {
                "schemas":[
                    "urn:ietf:params:scim:api:messages:2.0:PatchOp"
                ],
                "Operations":[{
                    "op":"add",
                    "path":"\(path)",
                    "value":[{
                        "enabled":true,
                        "keyHandle":"\(keyHandle)",
                        "algorithm":"\(self.currentFactor.algorithm)",
                        "publicKey":"\(publicKey)"
                    }]
                }]
            }
        """.data(using: .utf8)!
         
        // Create the resource to execute the request to enroll a signature factor and parse the result.
        let resource = HTTPResource<UUID>(.patch, url: url, accept: .json, contentType: .json, body: body, headers: ["Authorization": self.token.authorizationHeader]) { data, response in
            guard let _ = data else {
                return Result.failure(OnPremiseRegistrationError.dataInitializationFailed)
            }
            
            return Result.success(id)
        }
        
        let result = try await self.urlSession.dataTask(for: resource)
        
        if self.currentFactor.type == .fingerprint {
            self.factors.append(.fingerprint(FingerprintFactorInfo(id: result, name: name, algorithm: algorithm)))
        }
        else {
            self.factors.append(.userPresence(UserPresenceFactorInfo(id: result, name: name, algorithm: algorithm)))
        }
    }

    public func finalize() async throws -> OnPremiseAuthenticator {
        return OnPremiseAuthenticator(refreshUri: self.metadata.registrationUri,
                                      transactionUri: self.metadata.transactionUri,
                                      theme: self.metadata.theme,
                                      token: self.token,
                                      id: self.authenitcatorId,
                                      serviceName: self.metadata.serviceName,
                                      accountName: self.accountName,
                                      allowedFactors: self.factors,
                                      qrloginUri: self.metadata.qrloginUri,
                                      ignoreSSLCertificate: self.initializationInfo.ignoreSSLCertificate,
                                      clientId: self.initializationInfo.clientId)
    }
    
    // MARK: - On-premise initialization
    internal struct InitializationInfo: Decodable {
        /// The endpoint location to complete or initialize an mutli-factor.
        let uri: URL
        
        /// The code which can be used as a  multi-factor registration or login.
        let code: String

        /// A Boolean value to ignore self-signed secure sockets layer (SSL) certifcates.
        ///
        /// When this flag is `true` a  [URLSessionDelegate](https://developer.apple.com/documentation/foundation/urlsessiondelegate/1409308-urlsession) should be assigned to the `URLSession` to validate authentication challenges. For example certificate pinning.
        let ignoreSSLCertificate: Bool

        /// The unique identifier between the service and the client app.
        let clientId: String

        /// The root level JSON structure for decoding.
        private enum CodingKeys: String, CodingKey {
            case code
            case options
            case uri = "details_url"
            case version
            case clientId = "client_id"
        }

        /// Creates a new instance by decoding from the given decoder
        /// - Parameter decoder: The decoder to read data from.
        public init(from decoder: Decoder) throws {
            // Metadata keys
            let rootContainer = try decoder.container(keyedBy: CodingKeys.self)

            self.code = try rootContainer.decode(String.self, forKey: .code)
            self.uri = try rootContainer.decode(URL.self, forKey: .uri)
            self.clientId = try rootContainer.decode(String.self, forKey: .clientId)

            // Manually parse out the options as key-value pair separated by a comma.  i.e key=value,key=value
            var ignoreSSLCertificate = false
            if let options = try rootContainer.decodeIfPresent(String.self, forKey: .options) {
                let _ = options.components(separatedBy: ",")
                    .map({ $0.components(separatedBy: "=") })
                    .reduce(into: Bool()) { _, item in
                        if item[0] == "ignoreSslCerts" {
                            ignoreSSLCertificate = NSString(string: item[1]).boolValue
                        }
                    }
            }

            self.ignoreSSLCertificate = ignoreSSLCertificate
        }
    }

    // MARK: - On-premise metadata
    
    /// The metadata associated with the service.
    internal struct Metadata: Decodable {
        /// The domain of the site or app.
        let serviceName: String
        
        /// The registration location endpoint URL.
        let registrationUri: URL

        /// The transaction location endpoint URL.
        let transactionUri: URL
        
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
        
        /// The collection of available enrollment factors.
        var availableFactors: [EnrollableFactor] = []

        /// A custom color scheme that can be applied to app elements.  For example, buttons, background-color, text color.
        let theme: [String: String]

        /// Used to define features that can be applied to an app.
        let features: [String]
    
        // MARK: Enums

        /// The root level JSON structure for decoding.
        private enum CodingKeys: String, CodingKey {
            case transactionUri = "authntrxn_endpoint"
            case metadata
            case discoveredMechanisms = "discovery_mechanisms"
            case enrollmentUri = "enrollment_endpoint"
            case totpUri = "totp_shared_secret_endpoint"
            case tokenUri = "token_endpoint"
            case qrloginUri = "qrlogin_endpoint"
        }
        
        /// The `metadata` decoding structure.
        private enum MetadataCodingKeys: String, CodingKey {
            case serviceName = "service_name"
            case qrloginUri = "qrlogin_endpoint"
            case theme = "theme"
        }
        
        /// The "discoveredmechanisms" decoding structure based off `CodingKeys`.
        private enum DiscoveredMechanisms: String {
            case totp = "urn:ibm:security:authentication:asf:mechanism:totp"
            case fingerprint = "urn:ibm:security:authentication:asf:mechanism:mobile_user_approval:fingerprint"
            case userpresence = "urn:ibm:security:authentication:asf:mechanism:mobile_user_approval:user_presence"
        }
        
        /// Creates a new instance by decoding from the given decoder
        /// - parameter decoder: The decoder to read data from.
        public init(from decoder: Decoder) throws {
            let rootContainer = try decoder.container(keyedBy: CodingKeys.self)
            
            self.registrationUri = try rootContainer.decode(URL.self, forKey: .tokenUri)
            self.transactionUri = try rootContainer.decode(URL.self, forKey: .transactionUri)
            self.features = []
            
            let signatureUri = try rootContainer.decode(URL.self, forKey: .enrollmentUri)
            let totpUri = try rootContainer.decode(URL.self, forKey: .totpUri)
            
            // Metadata Keys
            let metadataContainer = try rootContainer.nestedContainer(keyedBy: MetadataCodingKeys.self, forKey: .metadata)
            self.serviceName = try metadataContainer.decodeIfPresent(String.self, forKey: .serviceName) ?? signatureUri.host!
            self.theme = try metadataContainer.decodeIfPresent([String: String].self, forKey: .theme) ?? [:]
         
            // Check if the QR login is present, otherwise check in the metadata.
            if let qrloginUri = try rootContainer.decodeIfPresent(URL.self, forKey: .qrloginUri) {
                self.qrloginUri = qrloginUri
            }
            else {
                self.qrloginUri = try metadataContainer.decodeIfPresent(URL.self, forKey: .qrloginUri)
            }

            // Get the values to assign to signature and one-time passcode authentication factors.
            var availableFactors: [EnrollableFactor] = []
            
            // If the "discovered_mechanisms" JSON data is present, create the authentication methods.
            if let mechanisms = try rootContainer.decodeIfPresent([String].self, forKey: .discoveredMechanisms) {
                // Check if userpresence signature is present.
                if mechanisms.contains(DiscoveredMechanisms.userpresence.rawValue) {
                    let factor = SignatureEnrollableFactor(uri: signatureUri, type: .userPresence, algorithm: "SHA512withRSA")
                    availableFactors.append(factor)
                }
                
                // Check if fingerprint signature is present.
                if mechanisms.contains(DiscoveredMechanisms.fingerprint.rawValue) {
                    let factor = SignatureEnrollableFactor(uri: signatureUri, type: .fingerprint, algorithm: "SHA512withRSA")
                    availableFactors.append(factor)
                }
                
                // Check if totp is present.
                if mechanisms.contains(DiscoveredMechanisms.totp.rawValue) {
                    let factor = OnPremiseTOTPEnrollableFactor(uri: totpUri)
                    availableFactors.append(factor)
                }
            }
            
            self.availableFactors = availableFactors
        }
    }
}
