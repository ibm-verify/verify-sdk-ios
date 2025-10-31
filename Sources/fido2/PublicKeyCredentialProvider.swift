//
// Copyright contributors to the IBM Verify FIDO2 SDK for iOS project
//

import Foundation
import CryptoKit
import LocalAuthentication
import os.log
import UIKit

/// A type that indicates when Fido2ApiClient encounters an error.
public enum PublicKeyCredentialError: Error, LocalizedError, Equatable {
    /// Authentication data or client data hash is invalid.
    case invalidAttestationData
    
    /// The private key data provided was invalid.
    case invalidPrivateKeyData
    
    /// The certifcate could not be parsed.
    case invalidCertificate
    
    /// A private key could not be created from the the private key data.
    case unableToCreateKey
    
    /// Unable to create a signature based on the private key and attestation data.
    case unableToCreateSignature
    
    /// The time allocated to complete the operation has expired.
    case timeout
    
    /// General error with custom message.
    case general(message: String)
    
    public var errorDescription: String? {
       switch self {
       case .invalidAttestationData:
            return NSLocalizedString("Authentication data or client data hash is invalid.", comment: "Invalid attestation data")
       case .invalidPrivateKeyData:
            return NSLocalizedString("The private key data provided was invalid.", comment: "Invalid private key")
       case .invalidCertificate:
           return NSLocalizedString("The certifcate could not be parsed.", comment: "Invalid certificate")
       case .unableToCreateKey:
            return NSLocalizedString("A private key could not be created from the the private key data.", comment: "Create key error.")
       case .unableToCreateSignature:
            return NSLocalizedString("Unable to create a signature based on the private key and attestation data.", comment: "Create signature error.")
       case .timeout:
            return NSLocalizedString("The time allocated to complete the operation has expired.", comment: "Timeout")
       case .general(message: let message):
           return NSLocalizedString(message, comment: "General Error")
       }
   }
}

/// Platform authentication for providing public key credential requests to an app using the [W3C Web Authentication](https://www.w3.org/TR/webauthn-2/) specification.
public class PublicKeyCredentialProvider {
    /// Create the object.
    public init() {
    }
    
    /// A delegate that the public key provider informs about the success or failure of an attestation or assertion attempt.
    public weak var delegate: PublicKeyCredentialDelegate?
    
    /// Creates a public key credential registration request with the authenticator identifier, attestation format provider and options representing the request.
    /// - Parameters:
    ///   - aaguid: The AAGUID of the authenticator.  Default is  "00000000-0000-0000-0000-000000000000".
    ///   - statementProvider: Represents a type of signed data object, containing statements about a public key credential itself and the authenticator that created it.  Default is `NoneAttestation`.
    ///   - options: An instance of `PublicKeyCredentialCreationOptions`.
    ///
    /// When the request succeeds, the information is relayed to the view controllers `delegate` by calling the `publicKeyCredential(provider:didCompleteWithAttestation:)` method with the result.  If the request fails then `publicKeyCredential(provider:didCompleteWithError:)` is called instead.
    /// ```swift
    /// // Create the desired authenticator section criteria.
    /// let selectionCriteria = AuthenticatorSelectionCriteria(authenticatorAttachment: .none,
    ///     requireResidentKey: true,
    ///     userVerification: .preferred)
    ///
    /// // The host of relying party.
    /// let relyingPartyEntity = PublicKeyCredentialRpEntity(name: "mydomain.com")
    ///
    /// // The information about the user.
    /// let userEntity = PublicKeyCredentialUserEntity(id: "JohnD",
    ///     displayName: "John Doe",
    ///     name: "JohnD")
    ///
    /// // Construct a new creation options object. The challenge typically comes from your server.
    /// let options = PublicKeyCredentialCreationOptions(
    ///     rp: relyingPartyEntity,
    ///     user: userEntity,
    ///     challenge: UUID().uuidString,
    ///     authenticatorSelection: selectionCriteria)
    ///
    /// // Use the aaguid for the make and model of the authenticator. A relying party may use this to infer additional properties.
    /// let aaguid = UUID(uuidString: "6dc9f22d-2c0a-4461-b878-de61e159ec61")!
    ///
    /// // Attempt to generate the public key credential with a private key attestation.
    /// let provider = PublicKeyCredentialProvider()
    ///
    ///// Ensure you implement PublicKeyCredentialDelegate to get the callbacks.
    /// provider.delegate = self
    /// provider.createCredentialAttestationRequest(aaguid, statementProvider: SelfAttestation(aaguid), options: options)
    /// ```
    public func createCredentialAttestationRequest(_ aaguid: UUID = UUID().empty, statementProvider: AttestionStatementProvider = NoneAttestation(), options: PublicKeyCredentialCreationOptions) {
        
        // Check the attestation conveyance preference, if "direct" and no PackedAttestionStatementProvider assigned, then bail out.
        if options.attestation == .indirect || (options.attestation == .direct && statementProvider is NoneAttestation) {
            delegate?.publicKeyCredential(provider: self, didCompleteWithError: PublicKeyCredentialError.general(message: "Invalid attestion statement option provided."))
        }
        
        // Throw if user verification is discouraged.
        if options.authenticatorSelection.userVerification == .discouraged {
            delegate?.publicKeyCredential(provider: self, didCompleteWithError: PublicKeyCredentialError.general(message: "User verification 'discouraged' not supported."))
        }
        
        // Prompt for user presence before creating a new key. We do this now so that we have a
        // context we can immediately also use for signing if doing self attestation
        let context = LAContext()
        var error: Error? = nil
        let semaphore = DispatchSemaphore.init(value: 0)
        
        os_log("Evaluating biometry policy.", log: .crypto, type: .info)
        
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "User Verification") { (result, policyError) in
            error = policyError
            
            if result {
                // Local authentication successful, continue below
                os_log("Biometry policy successful.", log: .crypto, type: .info)
            }
            
            semaphore.signal()
        }
        
        // Uses the timeout for the user to respond to a biometric prompt.
        if semaphore.wait(timeout: .now() + DispatchTimeInterval.seconds(options.timeout / 1000)) == .timedOut {
            context.invalidate()
            os_log("Biometry verification timed out.", log: .crypto, type: .info)
            delegate?.publicKeyCredential(provider: self, didCompleteWithError: PublicKeyCredentialError.timeout)
        }

        if let error = error {
            delegate?.publicKeyCredential(provider: self, didCompleteWithError: error)
        }

        // Create a new key.
        let store = SecKeyStore()
        guard let privateKey = try? SecKeyStore().generate(context: context) else {
            delegate?.publicKeyCredential(provider: self, didCompleteWithError: PublicKeyCredentialError.unableToCreateKey)
            return
        }

        do {
            let key = Data(SHA256.hash(data: privateKey.publicKey.derRepresentation))
            try store.add(key.base64URLEncodedString(), key: privateKey)
        
            // Create the attestation payload.
            let result = try processPublicKeyAttestationResponse(aaguid, statementProvider: statementProvider, privateKey: privateKey, context: context, options: options)
            delegate?.publicKeyCredential(provider: self, didCompleteWithAttestation: result)
        }
        catch let error {
            delegate?.publicKeyCredential(provider: self, didCompleteWithError: error)
        }
    }
    
    /// Creates an assertion request with request options and additional client data parameters.
    /// - Parameters:
    ///   - options: An instance of ``PublicKeyCredentialRequestOptions``.
    ///   - clientDataParams: Additional key/values pairs to enrich `clientJSONData` assertion.
    ///
    /// When the request succeeds, the information is relayed to the view controllers `delegate` by calling the `publicKeyCredential(provider:didCompleteWithAssertion:)` method with the result.  If the request fails then `publicKeyCredential(provider:didCompleteWithError:)` is called instead.
    /// ```swift
    /// // Construct a new request options object. The challenge typically comes from your server.
    /// let options = PublicKeyCredentialRequestOptions(
    ///     challenge: UUID().uuidString,
    ///     rp: "mydomain.com",
    ///     allowCredentials: [],
    ///     userVerification: .required,
    ///     timeout: 10000)
    ///
    /// // Attempt to generate the public key credential with a private key assertion.
    /// let provider = PublicKeyCredentialProvider()
    ///
    ///// Ensure you implement PublicKeyCredentialDelegate to get the callbacks.
    /// provider.delegate = self
    /// provider.createCredentialAssertionRequest(options: options)
    /// ```
    public func createCredentialAssertionRequest(options: PublicKeyCredentialRequestOptions, clientDataParams: [String:Any]? = [:]) {
        // Check if we have any extensions and if so, check if the biometry is Touch ID and if so, create an LAContext using extension message as the localized reason.
        var context: LAContext? = nil
        if let extensions = options.extensions, biometryType == .touchID {
            context = LAContext()
            context!.localizedReason = extensions.txAuthSimple
            
            os_log("Extension verification with Touch ID.", log: .crypto, type: .info)
        }
        
        // Create the private key from the stored data representation.
        var privateKey: SecureEnclave.P256.Signing.PrivateKey?
        let store = SecKeyStore()
        
        if let allowCredentials = options.allowCredentials {
            for credential in allowCredentials {
                privateKey = store.read(credential.id, context: context)
                if privateKey != nil {
                    break
                }
            }
        }
        
        // No private key found, bail out.
        if privateKey == nil {
            delegate?.publicKeyCredential(provider: self, didCompleteWithError: PublicKeyCredentialError.invalidPrivateKeyData)
        }
        
        DispatchQueue.main.async {
            if let extensions = options.extensions, self.biometryType == .faceID {
                if let viewController = self.viewController {
                    os_log("Extension verification with Face ID.", log: .webauthn, type: .info)
                    
                    // Prompt for extension signing.
                    let alert = self.createUserVerificationAlert(extensions.txAuthSimple)
                    alert.addAction(UIAlertAction(title: "Cancel", style: .cancel, handler: { action in
                        self.timer?.invalidate()
                        self.timer = nil
                        self.delegate?.publicKeyCredential(provider: self, didCompleteWithError: PublicKeyCredentialError.general(message: "User verification cancelled."))
                        alert.dismiss(animated: true)
                    }))
                    
                    alert.addAction(UIAlertAction(title: "Continue with Face ID", style: .default, handler: { action in
                        self.timer?.invalidate()
                        self.timer = nil
                        
                        do {
                            let result = try self.processPublicKeyAssertionResponse(options: options, privateKey: privateKey!, params: clientDataParams)
                            self.delegate?.publicKeyCredential(provider: self, didCompleteWithAssertion: result)
                            alert.dismiss(animated: true)
                        }
                        catch let error {
                            self.delegate?.publicKeyCredential(provider: self, didCompleteWithError: error)
                            alert.dismiss(animated: true)
                        }
                    }))
                    
                    viewController.present(alert, animated: true)
                    
                    self.timer = Timer.scheduledTimer(withTimeInterval: Double(options.timeout / 1000), repeats: false) { timer in
                        // The timer fired before the button was pressed
                        self.timer = nil
                        self.delegate?.publicKeyCredential(provider: self, didCompleteWithError: PublicKeyCredentialError.timeout)
                    
                        alert.dismiss(animated: true)
                    }
                }
                else {
                    self.delegate?.publicKeyCredential(provider: self, didCompleteWithError: PublicKeyCredentialError.general(message: "No view controller to display user verification."))
                }
            }
            else {
                // Create the attestation payload.
                do {
                    let result = try self.processPublicKeyAssertionResponse(options: options, privateKey: privateKey!, params: clientDataParams)
                    self.delegate?.publicKeyCredential(provider: self, didCompleteWithAssertion: result)
                }
                catch let error {
                    self.delegate?.publicKeyCredential(provider: self, didCompleteWithError: error)
                }
            }
        }
    }
    
    // MARK: Private variables
    
    /// Timer to handle user verification dialog.
    private var timer: Timer? = nil
    
    /// Gets the `LABiometryType` supported by the device.
    private var biometryType: LABiometryType {
        var error: NSError?
        let context = LAContext()
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return .none
        }
        
        return context.biometryType
    }
    
    /// Gets the top `UIViewController` in the stack.
    var viewController: UIViewController? {
        guard let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene, let sceneDelegate = windowScene.delegate as? UIWindowSceneDelegate, let window = sceneDelegate.window else {
            return nil
        }
        
        return window?.rootViewController
    }
        
    
    // MARK: Private methods
    
    private func processPublicKeyAttestationResponse(_ aaguid: UUID, statementProvider: AttestionStatementProvider, privateKey: SecureEnclave.P256.Signing.PrivateKey, context: LAContext, options: PublicKeyCredentialCreationOptions) throws -> PublicKeyCredential<AuthenticatorAttestationResponse> {
    
        // MARK: Build the id and rawId
        // 1. Create id as Data. The id whose value is also the rawId and credentialId.
        let id = Data(SHA256.hash(data: privateKey.publicKey.derRepresentation))
        
        // MARK: Build clientData JSON and hash
        // 1. Create a dictionary of the values.
        let clientDataParams = ["origin": "https://\(options.rp.id!)",
                                "challenge": options.challenge,
                                "type": "webauthn.create"]
        
        // 2. Serialize the dictionary to a Data object.
        let clientData = try! JSONSerialization.data(withJSONObject: clientDataParams, options: [])
        
        // 3. Convert the Data object to JSON.
        let clientDataJSON = String(decoding: clientData, as: UTF8.self)
        
        // 4. Hash the JSON with SHA256
        let clientDataHash = Data(SHA256.hash(data: clientData))
        
        // MARK: Build authenticatorData
        // https://w3c.github.io/webauthn/#sctn-attestation
        // 1. Create an empty byte array
        var authenticatorDataParams: [UInt8] = []
        
        // 2. Add hash of rp.id
        authenticatorDataParams.append(contentsOf: SHA256.hash(data: options.rp.id!.data(using: .utf8)!))
        
        // 3. Add the flags (userPresence | userVerification | extension)
        authenticatorDataParams.append(UInt8(0x01 | 0x04 | 0x40))
        
        // 4. Add the counter being 4 bytes
        let now = Int(Date().timeIntervalSince1970)
        let counter: [UInt8] = [UInt8((now & 0xff000000) >> 24), UInt8((now & 0x00ff0000) >> 16), UInt8((now & 0x0000ff00) >>  8), UInt8(now & 0x000000ff)]

        authenticatorDataParams.append(contentsOf: counter)
        
        // MARK: Build attestedCredentialData
        // 1. Create an empty byte array
        var attestedCredentailDataParam: [UInt8] = []
        
        // 2. Add 16 byte aaguid
        attestedCredentailDataParam.append(contentsOf: aaguid.uuidArray)
        
        // 3. Add the length of the credentiald
        let length: [UInt8] = [UInt8((id.count & 0xff00) >> 8), UInt8((id.count & 0x00ff))]
        attestedCredentailDataParam.append(contentsOf: length)
        
        // 4. Add the credentialId
        attestedCredentailDataParam.append(contentsOf: [UInt8](id))
        
        // 5. Convert the public key DER to COSE format.
        let publicKeyDER = privateKey.publicKey.derRepresentation
        let publicKeyCOSE = COSEKeyEC2(alg: -7, crv: 1, xCoord: Array(publicKeyDER[27..<59]), yCoord: Array(publicKeyDER[59..<91]))
        attestedCredentailDataParam.append(contentsOf: publicKeyCOSE.bytes)
        
        // 6. Add attestedCredential to authenticatorData
        authenticatorDataParams.append(contentsOf: attestedCredentailDataParam)
        
        // 7. Build attestation if required
        var attStmt = [String: Any]()
        
        if options.attestation == .direct && statementProvider is PackedAttestionStatementProvider {
            var attestationFormat: PackedAttestionStatementProvider = statementProvider as! PackedAttestionStatementProvider
            attestationFormat.authenticatorData = Data(authenticatorDataParams)
            attestationFormat.clientDataHash = clientDataHash
            
            if attestationFormat is SelfAttestation, var selfAttestation = attestationFormat as? SelfAttestation {
                let privateKey = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: privateKey.dataRepresentation, authenticationContext: context)
                selfAttestation.privateKey = privateKey
                attestationFormat = selfAttestation
            }
                            
            do {
                attStmt = try attestationFormat.statement()
            }
            catch let error {
                throw error
            }
        }
        
        // MARK: Build attestedObject
        // 1. Create dictionary to store attestation segments.
        var attestedObject = [String: Any]()
        attestedObject.updateValue(authenticatorDataParams, forKey: "authData")
        attestedObject.updateValue(statementProvider.format, forKey: "fmt")
        attestedObject.updateValue(attStmt, forKey: "attStmt")

        // 2. Convert the dictionary to CBOR
        let attestedObjectParams = CBORWriter().putStringKeyMap(attestedObject).getResult()
        
        // 3. Build the response
        let response = AuthenticatorAttestationResponse(clientDataJSON: clientDataJSON, attestationObject: attestedObjectParams)

        return PublicKeyCredential<AuthenticatorAttestationResponse>(rawId: id.base64URLEncodedString(), id: id.base64URLEncodedString(), response: response, getTransports: ["internal"])
    }
    
    private func processPublicKeyAssertionResponse(options: PublicKeyCredentialRequestOptions, privateKey: SecureEnclave.P256.Signing.PrivateKey, params: [String: Any]? = [:]) throws -> PublicKeyCredential<AuthenticatorAssertionResponse> {
        // MARK: Build the id and rawId
        // 1. Create id as Data. The id which value is also the rawId and credentialId.
        let id = Data(SHA256.hash(data: privateKey.publicKey.derRepresentation))
        
        // MARK: Build clientData JSON and hash
        // 1. Create a dictionary of the values.
        var clientDataParams: [String: Any] = ["origin": "https://\(options.rpId!)",
                                              "challenge": options.challenge,
                                              "type": "webauthn.get"]
        
        // Append the additional params to the JSON request.
        if let params = params {
            clientDataParams.merge(params) { (current, _) in current }
        }
        
        // 2. Serialize the dictionary to a Data object.
        let clientData = try! JSONSerialization.data(withJSONObject: clientDataParams, options: [])
        
        // 3. Convert the Data object to JSON.
        let clientDataJSON = String(decoding: clientData, as: UTF8.self)
        
        // 4. Hash the JSON with SHA256.
        let clientDataHash = SHA256.hash(data: clientData)
        
        
        // MARK: Build authenticatorData
        // https://w3c.github.io/webauthn/#sctn-op-get-assertion
        // 1. Create an empty byte array
        var authenticatorDataParams: [UInt8] = []
        
        // 2. Add hash of rp.id
        authenticatorDataParams.append(contentsOf: SHA256.hash(data: options.rpId!.data(using: .utf8)!))
        
        // 3. Add the flags
        var flags = UInt8(0x01) // userPresence (UP)
        flags |= 0x04           // userVerification (UV)
        
        if options.extensions != nil {
            flags |= 0x80       // authenticatorExtensions (ED)
        }
        
        authenticatorDataParams.append(flags)
        
        // 4. Add the counter being 4 bytes
        let now = Int(Date().timeIntervalSince1970)
        let counter: [UInt8] = [UInt8((now & 0xff000000) >> 24), UInt8((now & 0x00ff0000) >> 16), UInt8((now & 0x0000ff00) >>  8), UInt8(now & 0x000000ff)]

        authenticatorDataParams.append(contentsOf: counter)
        
        // MARK: Build extension, if applicable
        
        // 1. Add the extension data if present.  Must be in CBOR format.
        if let extensions = options.extensions {
            let writer = CBORWriter().putStringKeyMap(["txAuthSimple": extensions.txAuthSimple])
            authenticatorDataParams.append(contentsOf: writer.getResult())
        }
        
        // MARK: Build authenticator param and client data hash - signature base string
        // 1. Create an empty byte array
        var signatureBase: [UInt8] = []
        
        // 2. Add a authenticatorData
        signatureBase.append(contentsOf: authenticatorDataParams)
        
        // 3. Add a hash of clientJSONData.
        signatureBase.append(contentsOf: clientDataHash)
        
        // 5. Sign the signatureBase.
        do {
            let signature = try privateKey.signature(for: signatureBase)
        
            // 6. Build the response
            let response = AuthenticatorAssertionResponse(clientDataJSON: clientDataJSON, authenticatorData: authenticatorDataParams, signature: Array(signature.derRepresentation), userHandle: nil)
        
            return PublicKeyCredential<AuthenticatorAssertionResponse>(rawId: id.base64URLEncodedString(), id: id.base64URLEncodedString(), response: response)
        }
        catch let error {
            os_log("Signing error %{public}@", log: .webauthn, type: .debug, error.localizedDescription)
            throw error
        }
    }
    
    // Creates an `UIAlertViewController` which is presented when `PublicKeyCredentialRequestOptions.extensions` are present.
    private func createUserVerificationAlert(_ message: String) -> UIAlertController {
        // Construct the UIAlertViewController
        let alert = UIAlertController(title: "User Verification", message: message, preferredStyle: .alert)
        
        // Update the biometry image position and add to alert view controller.
        let topConstant = calculateImageTopOfset(for: message)
        alert.message? += "\n\n\n\n"

        let imageView = UIImageView(frame: CGRect(x: 0, y: 0, width: 56, height: 56))
        imageView.image = UIImage(systemName: "faceid")
        imageView.translatesAutoresizingMaskIntoConstraints = false
        alert.view.addSubview(imageView)
        
        // Add the constraints for the image to center.
        alert.view.addConstraints([
            NSLayoutConstraint(item: imageView, attribute: .centerX, relatedBy: .equal, toItem: alert.view, attribute: .centerX, multiplier: 1, constant: 0),
            NSLayoutConstraint(item: imageView, attribute: .top, relatedBy: .equal, toItem: alert.view, attribute: .top, multiplier: 1, constant: topConstant),
            NSLayoutConstraint(item: imageView, attribute: .width, relatedBy: .equal, toItem: nil, attribute: .notAnAttribute, multiplier: 1, constant: 56),
            NSLayoutConstraint(item: imageView, attribute: .height, relatedBy: .equal, toItem: nil, attribute: .notAnAttribute, multiplier: 1, constant: 56)
        ])
        
        return alert
    }

    /// Calculates the top offset position for the biometry image based on the message character count.
    /// - Parameter message: The message string.
    /// - Returns: The float that is used for the constraint.
    private func calculateImageTopOfset(for message: String) -> CGFloat {
        let characterPerLine = 33
        let numberOfLines = ceil(CGFloat(message.count) / CGFloat(characterPerLine))
        return 56 + numberOfLines * 16
        
    }
}

// MARK: Protocols

/// An interface for providing information about the outcome of an attestation or assertion attempt.
public protocol PublicKeyCredentialDelegate: AnyObject {
    /// Tells the delegate when an attestion or assertion attempt fails, and provides an error explaining why.
    /// - Parameters:
    ///   - provider: The provider that performs the attestation or assertion attempt.
    ///   - error: An error that explains the failure.
    func publicKeyCredential(provider: PublicKeyCredentialProvider, didCompleteWithError error: Error)
    
    /// Tells the delegate when attestation attempt completes successfully.
    /// - Parameters:
    ///   - provider: The provider that performs the attestation attempt.
    ///   - result: The authenticator attestation response.
    func publicKeyCredential(provider: PublicKeyCredentialProvider, didCompleteWithAttestation result: PublicKeyCredential<AuthenticatorAttestationResponse>)
    
    
    /// Tells the delegate when attestation attempt completes successfully.
    /// - Parameters:
    ///   - provider: The provider that performs the assertion attempt.
    ///   - result: The authenticator assertion response.
    func publicKeyCredential(provider: PublicKeyCredentialProvider, didCompleteWithAssertion result: PublicKeyCredential<AuthenticatorAssertionResponse>)
}

// MARK: Protocol Extension Defaults

/// An interface for providing information about the outcome of an attestation or assertion attempt.
public extension PublicKeyCredentialDelegate {
    /// Tells the delegate when attestation attempt completes successfully.
    /// - Parameters:
    ///   - provider: The provider that performs the attestation attempt.
    ///   - result: The authenticator attestation response.
    func publicKeyCredential(provider: PublicKeyCredentialProvider, didCompleteWithAttestation result: PublicKeyCredential<AuthenticatorAttestationResponse>) {
    }
    
    /// Tells the delegate when attestation attempt completes successfully.
    /// - Parameters:
    ///   - provider: The provider that performs the assertion attempt.
    ///   - result: The authenticator assertion response.
    func publicKeyCredential(provider: PublicKeyCredentialProvider, didCompleteWithAssertion result: PublicKeyCredential<AuthenticatorAssertionResponse>) {
    }
}
