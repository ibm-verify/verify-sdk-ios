//
// Copyright contributors to the IBM Verify MFA Sample App for iOS project
//

import Foundation
import MFA
import Core
import CryptoKit
import SwiftUI

@MainActor
class RegistrationViewModel: ObservableObject {
    private var dataManager: DataManager = DataManager()
    
    @Published var accountName: String = String()
    @Published var errorMessage: String = String()
    @Published var navigate: Bool = false
    @Published var isPresentingErrorAlert: Bool = false
    
    // Validates the QR code.
    func validateCode(code: String) async {
        let controller = MFARegistrationController(json: code)
        
        do {
            let provider = try await controller.initiate(with: self.accountName)
                    
            while let factor = await provider.nextEnrollment() {
                print("Enrolling \(factor)")
                
                // Get the next enrollable signature.
                guard let factor = await provider.nextEnrollment() else {
                   return
                }

                // Create the key-pair using default SHA512 hash.
                let key = RSA.Signing.PrivateKey()
                
                // Sign the data with the private key.
                let signature = try sign(privateKey: key, factor: factor)

                // Add to the Keychain.
                try KeychainService.default.addItem("biometric", value: key.derRepresentation, accessControl: factor.biometricAuthentication ? .biometryCurrentSet : nil)
               
                // Enroll the factor.
                try await provider.enroll(with: "biometric", publicKey: key.publicKey.x509Representation, signedData: signature)

                // try await provider.enroll()
            }
           
            // Generate the authenticator
            let authenticator = try await provider.finalize()
            await saveAuthenticator(authenticator: authenticator)
            
            navigate = true
        }
        catch let error {
            print(error.localizedDescription)
            errorMessage = error.localizedDescription
            isPresentingErrorAlert = true
        }
    }
    
    func saveAuthenticator(authenticator: (any MFAAuthenticatorDescriptor)) async {
        do {
            try dataManager.save(authenticator: authenticator)
        }
        catch let error {
            errorMessage = error.localizedDescription
            isPresentingErrorAlert = true
        }
    }
    
    func sign(privateKey: RSA.Signing.PrivateKey, factor: EnrollableSignature) throws -> String {
        // Create the signature with the hash
        if factor.algorithm == .sha256 {
            let value = SHA256.hash(data:  Data(factor.dataToSign.utf8))
            let signature = try privateKey.signature(for: value)
            return signature.rawRepresentation.base64UrlEncodedString()
        }
        else if factor.algorithm == .sha384 {
            let value = SHA384.hash(data:  Data(factor.dataToSign.utf8))
            let signature = try privateKey.signature(for: value)
            return signature.rawRepresentation.base64UrlEncodedString()
        }
        else if factor.algorithm == .sha512 {
            let value = SHA512.hash(data:  Data(factor.dataToSign.utf8))
            let signature = try privateKey.signature(for: value)
            return signature.rawRepresentation.base64UrlEncodedString()
        }
        
        throw MFAServiceError.invalidSigningHash
    }
}
