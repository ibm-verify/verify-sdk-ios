//
// Copyright contributors to the IBM Verify FIDO2 Sample App for iOS project
//

import UIKit
import LocalAuthentication
import CryptoKit
import os.log
import FIDO2

class AttestationViewController: UIViewController {
    // MARK: Control variables
    @IBOutlet weak var buttonOption: UIButton!
    @IBOutlet weak var labelRp: UILabel!
    @IBOutlet weak var labelAccessToken: UILabel!
    
    // MARK: Variables
    var displayName: String?
    var accessToken: String?
    var rpUrl: String?
    var userName: String?
    var server = isv
    var params: [String: Any] = [:]
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Apply some styling to the visual controls.
        buttonOption.setCornerRadius()
        
        guard let accessToken = accessToken, let rpUrl = rpUrl else {
            return
        }
        
        labelRp.text = "\(rpUrl)/attestation/options"
        labelAccessToken.text = accessToken
    }
    
    override func prepare(for segue: UIStoryboardSegue, sender: Any?) {
        if let viewController = segue.destination as? AttestationInfoViewController, let options = sender as? PublicKeyCredentialCreationOptions {
            viewController.options = options
            viewController.accessToken = accessToken!
            viewController.rpUrl = "\(rpUrl!)"
            viewController.params = self.params
            viewController.username = self.userName
            viewController.displayName = self.displayName
            viewController.server = self.server
            viewController.isModalInPresentation = true
        }
    }
    
    // MARK: Control events
    
    @IBAction func onOptionClick(_ sender: UIButton) {
        // Validate before submitting.
        guard let relyingPartyUrl = labelRp.text, let accessToken = accessToken else {
            let alertController = UIAlertController(title: "FIDO2 Example", message: "The replying party or access token are not available.", preferredStyle: .alert)
            alertController.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
            
            self.present(alertController, animated: true)
            return
        }
        
        buttonOption.setActivity(true)
        
        if self.server == isva, let username = userName {
            params.updateValue(username, forKey: "username")
        }
        
        FidoService.shared.fetchAttestationOptions(relyingPartyUrl, accessToken: accessToken) { result in
            self.buttonOption.setActivity(false)
            
            switch result {
            case .success(let value):
                // Transition to info view controller.
                DispatchQueue.main.async {
                    self.performSegue(withIdentifier: "ShowAttestationOptionsInfo", sender: value)
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

