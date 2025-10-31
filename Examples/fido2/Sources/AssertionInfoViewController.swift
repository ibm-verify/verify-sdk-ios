//
// Copyright contributors to the IBM Verify FIDO2 Sample App for iOS project
//

import Foundation
import UIKit
import os.log
import FIDO2

class AssertionInfoViewController: UIViewController {
    // MARK: Control variables
    @IBOutlet weak var activityIndicator: UIActivityIndicatorView!
    @IBOutlet weak var buttonClose: UIButton!
    @IBOutlet weak var stackviewProperties: UIStackView!
    @IBOutlet weak var labelProgress: UILabel!
    
    // MARK: Variables
    var assertion: PublicKeyCredential<AuthenticatorAssertionResponse>?
    var success = false
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        activityIndicator.startAnimating()
        self.activityIndicator.isHidden = false
        
        let relyingPartyUrl = UserDefaults.standard.string(forKey: Store.relyingPartyUrl.rawValue)!
        let accessToken = UserDefaults.standard.string(forKey: Store.accessToken.rawValue)!
        let username = UserDefaults.standard.string(forKey: Store.username.rawValue) ?? ""
        
        let assertionUrl = "\(relyingPartyUrl)/assertion/result"
        
        // Perform the authentication
        if let server = UserDefaults.standard.string(forKey: Store.server.rawValue) {
            if server == isva {
                FidoService.shared.assertAuthenticator(assertionUrl, accessToken: accessToken, username: username, assertion: assertion!, type: ISVAAssertionResponse.self) { result in
                    DispatchQueue.main.async {
                        self.activityIndicator.stopAnimating()
                        self.activityIndicator.isHidden = true
                        self.labelProgress.isHidden = true
                    }
                    
                    switch result {
                    case .success(let response):
                        Logger.app.info("Authenticator successfully signed!")
                        self.success = true
                        
                        DispatchQueue.main.async {
                            self.displayCredentialProperties(userData: response)
                        }
                                
                    case .failure(let error):
                        let alertController = UIAlertController(title: "FIDO2 Example", message: error.localizedDescription, preferredStyle: .alert)
                        alertController.addAction(UIAlertAction(title: "OK", style: .default, handler: { action in
                            DispatchQueue.main.async {
                                self.performSegue(withIdentifier: "unwindToAssertionView", sender: self)
                            }
                        }))

                        DispatchQueue.main.async {
                            self.present(alertController, animated: true)
                        }
                    }
                }
            }
            else {
                FidoService.shared.assertAuthenticator(assertionUrl, accessToken: accessToken, username: username, assertion: assertion!, type: ISVAssertionResponse.self) { result in
                    DispatchQueue.main.async {
                        self.activityIndicator.stopAnimating()
                        self.activityIndicator.isHidden = true
                        self.labelProgress.isHidden = true
                    }
                    
                    switch result {
                    case .success(let response):
                        Logger.app.info("Authenticator successfully signed!")
                        self.success = true
                        
                        DispatchQueue.main.async {
                            self.displayCredentialProperties(userData: response)
                        }
                                
                    case .failure(let error):
                        let alertController = UIAlertController(title: "FIDO2 Example", message: error.localizedDescription, preferredStyle: .alert)
                        alertController.addAction(UIAlertAction(title: "OK", style: .default, handler: { action in
                            DispatchQueue.main.async {
                                self.performSegue(withIdentifier: "unwindToAssertionView", sender: self)
                            }
                        }))

                        DispatchQueue.main.async {
                            self.present(alertController, animated: true)
                        }
                    }
                }
            }
        }
    }
    
    /// Renders the credential user data to the screen.
    /// - parameter userData: An instance of `CredentialUserData`
    private func displayCredentialProperties<T: AssertionResponse>(userData: T) {
        if let response = userData as? ISVAAssertionResponse {
            // If there is an icon, create it
            if let imageString = response.attributes[.icon] as? String, let url = URL(string: imageString), let data = try? Data(contentsOf: url), let image = UIImage(data: data) {
                
                let property = createImage(image: image)
                stackviewProperties.addArrangedSubview(property)
            }
            
            // Dynamically add the labels to the stackview
            let property1 = createLabels(heading: "Username", text: response.username)
            stackviewProperties.addArrangedSubview(property1)
        
            let property2 = createLabels(heading: "Display name", text: response.displayName)
            stackviewProperties.addArrangedSubview(property2)
            
            let property3 = createLabels(heading: "Email", text: response.email)
            stackviewProperties.addArrangedSubview(property3)
            
            let property4 = createLabels(heading: "Authenticator nickname", text: response.nickname)
            stackviewProperties.addArrangedSubview(property4)
            
            if let value = response.attributes[.description] as? String {
                let property = createLabels(heading: "Authenticator description", text: value)
                stackviewProperties.addArrangedSubview(property)
            }
            
            if let value = response.attributes[.txAuthSimple] as? String {
                let property = createLabels(heading: "Transaction confirmation", text: value)
                stackviewProperties.addArrangedSubview(property)
            }
            
            let property5 = createLabels(heading: "Relying party", text: response.rpId)
            stackviewProperties.addArrangedSubview(property5)
        }
        
        if let response = userData as? ISVAssertionResponse {
            // If there is an icon, create it
            if let imageString = response.attributes[.icon] as? String, let url = URL(string: imageString), let data = try? Data(contentsOf: url), let image = UIImage(data: data) {
                
                let property = createImage(image: image)
                stackviewProperties.addArrangedSubview(property)
            }
            
            // Dynamically add the labels to the stackview
            let property1 = createLabels(heading: "User id", text: response.userId)
            stackviewProperties.addArrangedSubview(property1)
        
            let property2 = createLabels(heading: "Authenticator nickname", text: response.nickname)
            stackviewProperties.addArrangedSubview(property2)
            
            let property3 = createLabels(heading: "Relying party", text: response.rpId)
            stackviewProperties.addArrangedSubview(property3)
            
            let property4 = createLabels(heading: "Authenticator type", text: response.type)
            stackviewProperties.addArrangedSubview(property4)
            
            if let value = response.attributes[.attestationFormat] as? String {
                let property = createLabels(heading: "Attestation format", text: value)
                stackviewProperties.addArrangedSubview(property)
            }
            
            if let value = response.attributes[.attestationType] as? String {
                let property = createLabels(heading: "Attestation type", text: value)
                stackviewProperties.addArrangedSubview(property)
            }
            
            if let value = response.attributes[.description] as? String {
                let property = createLabels(heading: "Description", text: value)
                stackviewProperties.addArrangedSubview(property)
            }
        }
    }
    
    private func createLabels(heading: String, text: String) -> UIStackView {
        // Create the 2 UILabels representing the title header and display text.
        let labelHeader = UILabel()
        labelHeader.text = heading
        labelHeader.textColor = .systemGray
        labelHeader.font = labelHeader.font.withSize(15)
        
        let labelText = UILabel()
        labelText.text = text
        labelText.numberOfLines = 0
        labelText.lineBreakMode = .byWordWrapping
        
        // Create a UIStackView to hold the labels.
        let stackview = UIStackView(arrangedSubviews: [labelHeader, labelText])
        stackview.axis = .vertical
        stackview.spacing = 12
        
        return stackview
    }
    
    private func createImage(image: UIImage) -> UIStackView {
        // Create the 2 UILabels representing the title header and display text.
        let imageView = UIImageView(frame: CGRect(x: 0, y: 0, width: 16, height: 16))
        imageView.image = image
        imageView.contentMode = .scaleAspectFit
        
        // Create a UIStackView to hold the labels.
        let stackview = UIStackView(arrangedSubviews:[imageView])
        stackview.axis = .vertical
        stackview.spacing = 12
        stackview.alignment = .leading
        
        return stackview
    }
    
    // MARK: Control events
    
    @IBAction func onCloseClick(_ sender: UIButton) {
        self.performSegue(withIdentifier: "unwindToAssertionView", sender: self)
    }
}
