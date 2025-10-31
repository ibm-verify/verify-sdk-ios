//
// Copyright contributors to the IBM Verify FIDO2 Sample App for iOS project
//

import UIKit

class WhoAmIViewController: UIViewController {
    // MARK: Control variables
    @IBOutlet weak var textfieldRp: UITextField!
    @IBOutlet weak var textfieldAccessToken: UITextField!
    @IBOutlet weak var buttonWhoAmI: UIButton!
    
    // MARK: Variable
    var accessToken: String?
    var rpUrl: String?
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // Set styling
        textfieldRp.setBorderBottom()
        textfieldAccessToken.setBorderBottom()
        buttonWhoAmI.setCornerRadius()
        
        // Handle UITextField events
        textfieldRp.delegate = self
        textfieldAccessToken.delegate = self
        
        textfieldRp.becomeFirstResponder()
    }
    
    // MARK: Control events
    
    override func prepare(for segue: UIStoryboardSegue, sender: Any?) {
        if let viewController = segue.destination as? AttestationViewController, let ivcreds = sender as? IVCreds {
            viewController.accessToken = textfieldAccessToken.text!
            viewController.rpUrl = textfieldRp.text!
            viewController.displayName = ivcreds.attributes!["name"] as? String
            viewController.userName = ivcreds.username
            viewController.server = isva
            viewController.isModalInPresentation = true
        }
    }
    
    @IBAction func onWhoAmI(_ sender: UIButton) {
        // Validate before submitting.
        guard let relyingPartyUrl = textfieldRp.text, !relyingPartyUrl.isEmpty, let accessToken = textfieldAccessToken.text, !accessToken.isEmpty  else {
            let alertController = UIAlertController(title: "FIDO2 Example", message: "Please enter all fields.", preferredStyle: .alert)
            alertController.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
            
            self.present(alertController, animated: true)
            return
        }
        
        buttonWhoAmI.setActivity(true)
        
        // Fetch WhoAmI first
        let url = IVCreds.buildURL(relyingPartyUrl)
        IVCreds.getWhoAmI(url, accessToken: accessToken) { result in
            self.buttonWhoAmI.setActivity(false)
            
            switch result {
            case .success(let ivcreds):
                DispatchQueue.main.async {
                    self.performSegue(withIdentifier: "ShowAttestation", sender: ivcreds)
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
