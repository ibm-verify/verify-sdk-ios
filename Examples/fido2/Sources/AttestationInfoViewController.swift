//
// Copyright contributors to the IBM Verify FIDO2 Sample App for iOS project
//

import Foundation
import UIKit
import CryptoKit
import os.log
import FIDO2

class AttestationInfoViewController: UIViewController {
    // MARK: Control variables
    @IBOutlet weak var buttonRegister: UIButton!
    @IBOutlet weak var buttonCancel: UIButton!
    @IBOutlet weak var textfieldNickname: UITextField!
    
    // MARK: Variables
    var options: PublicKeyCredentialCreationOptions? = nil
    var accessToken: String? = nil
    var username: String? = nil
    var displayName: String? = nil
    var rpUrl: String? = nil
    var server = isv
    var params: [String: Any] = [:]


    override func viewDidLoad() {
        super.viewDidLoad()
        // Apply some styling to the visual controls.
        textfieldNickname.setBorderBottom()
        textfieldNickname.becomeFirstResponder()
        
        buttonRegister.setCornerRadius()
                        
        // Hides the keyboard
        textfieldNickname.delegate = self
    }
    
    // MARK: Control events
    
    @IBAction func onCancelClick(_ sender: UIButton) {
        dismiss(animated: true)
    }
    
    @IBAction func onRegisterClick(_ sender: UIButton) {
        guard let options = options else {
            buttonRegister.isEnabled = false
            return
        }
        
        // MARK: Metadata UUID
        // The UUID string represents an identifier to the aaguid.  When configured with FIDO metadata, authenticators are validated and provide additional characistics. Refer to the metadata.json in the Sources folder.
        var uuid = "6dc9f22d-2c0a-4461-b878-de61e159ec61"
        if server == isv {
            uuid = "cdbdaea2-c415-5073-50f7-c04e968640b6"
        }
        
        let aaguid = UUID(uuidString: uuid)!
        let provider = PublicKeyCredentialProvider()
        provider.delegate = self
        provider.createCredentialAttestationRequest(aaguid, statementProvider: SelfAttestation(aaguid), options: options)
    }
}

extension AttestationInfoViewController: PublicKeyCredentialDelegate {
    func publicKeyCredential(provider: PublicKeyCredentialProvider, didCompleteWithError error: Error) {
        let alertController = UIAlertController(title: "FIDO2 Example", message: error.localizedDescription, preferredStyle: .alert)
        alertController.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))

        DispatchQueue.main.async {
            self.present(alertController, animated: true)
        }
    }
    
    func publicKeyCredential(provider: PublicKeyCredentialProvider, didCompleteWithAttestation result: PublicKeyCredential<AuthenticatorAttestationResponse>) {
        buttonRegister.setActivity(true)
        
        guard let rpUrl = rpUrl else {
            return
        }
        
        let attestationUrl = "\(rpUrl)/attestation/result"
        
        var nickname =  "\(UIDevice().name) - (\(UIDevice().model))"
        if !textfieldNickname.text!.isEmpty {
            nickname = textfieldNickname.text!
        }
        
        FidoService.shared.createAuthenticator(attestationUrl, accessToken: accessToken!, server: self.server, nickname: nickname, attestation: result) { result in
            self.buttonRegister.setActivity(false)

            switch result {
            case .success:
                Logger.app.info("Authenticator registered!")
                UserDefaults.standard.setValue(nickname, forKey: Store.nickname.rawValue)
                UserDefaults.standard.setValue(self.rpUrl, forKey: Store.relyingPartyUrl.rawValue)
                UserDefaults.standard.setValue(true, forKey: Store.created.rawValue)
                UserDefaults.standard.setValue(self.username, forKey: Store.username.rawValue)
                UserDefaults.standard.setValue(self.accessToken, forKey: Store.accessToken.rawValue)
                UserDefaults.standard.setValue(self.server, forKey: Store.server.rawValue)
                UserDefaults.standard.setValue(self.displayName, forKey: Store.displayName.rawValue)
                
                // Format the date.
                let dateFormatter = DateFormatter()
                dateFormatter.dateStyle = .full
                
                let timeFormatter = DateFormatter()
                timeFormatter.timeStyle = .medium
               
                let createdDate = "\(dateFormatter.string(from: Date())) \(timeFormatter.string(from: Date()))"
                
                UserDefaults.standard.setValue(createdDate, forKey: Store.createdDate.rawValue)
                
                DispatchQueue.main.async {
                    self.dismiss(animated: true) {
                        // Assign the root view controller.
                        let storybaord = UIStoryboard(name: "Main", bundle: nil)
                        let viewController = storybaord.instantiateViewController(withIdentifier: "authenticationLanding")
                        UIApplication.shared.windows.first?.rootViewController = UINavigationController(rootViewController: viewController)
                        UIApplication.shared.windows.first?.makeKeyAndVisible()
                    }
                }
            case .failure(let error):
                let alertController = UIAlertController(title: "FIDO2 Example", message: error.localizedDescription, preferredStyle: .alert)
                alertController.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))

                DispatchQueue.main.async {
                    self.present(alertController, animated: true)
                }
            }
        }
    }
}
