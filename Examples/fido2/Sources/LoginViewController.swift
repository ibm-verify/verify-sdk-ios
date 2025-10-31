//
// Copyright contributors to the IBM Verify FIDO2 Sample App for iOS project
//

import UIKit
import os.log
import FIDO2

class LoginViewController: UIViewController {
    // MARK: Control variables
    @IBOutlet weak var textfieldPassword: UITextField!
    @IBOutlet weak var textfieldTenant: UITextField!
    @IBOutlet weak var textfieldUsername: UITextField!
    @IBOutlet weak var textfieldClientId: UITextField!
    @IBOutlet weak var buttonLogin: UIButton!
    
    // MARK: Variable
    var accessToken: String?
    var rpUrl: String?
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // Set styling
        textfieldPassword.setBorderBottom()
        textfieldTenant.setBorderBottom()
        textfieldUsername.setBorderBottom()
        textfieldClientId.setBorderBottom()
        buttonLogin.setCornerRadius()
        
        // Handle UITextField events
        textfieldTenant.delegate = self
        textfieldUsername.delegate = self
        textfieldPassword.delegate = self
        textfieldClientId.delegate = self
        
        textfieldTenant.becomeFirstResponder()
    }
    
    // MARK: Control events
    
    override func prepare(for segue: UIStoryboardSegue, sender: Any?) {
        if let viewController = segue.destination as? AttestationViewController {
            viewController.accessToken = accessToken!
            viewController.rpUrl = rpUrl!
            viewController.server = isv
            viewController.userName = textfieldUsername.text!
            viewController.params = ["authenticatorSelection": ["requireResidentKey":true]]
            viewController.isModalInPresentation = true
        }
    }
    
    @IBAction func onLogin(_ sender: UIButton) {
        // Validate before submitting.
        guard let tenantUrl = textfieldTenant.text, !tenantUrl.isEmpty, let clientId = textfieldClientId.text, !clientId.isEmpty, let username = textfieldUsername.text, !username.isEmpty, let password = textfieldPassword.text, !password.isEmpty else {
            let alertController = UIAlertController(title: "FIDO2 Example", message: "Please enter all fields.", preferredStyle: .alert)
            alertController.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
            
            self.present(alertController, animated: true)
            return
        }
        
        buttonLogin.setActivity(true)
        
        // Perform the login attempt.
        login(url: tenantUrl, clientId: clientId, username: username, password: password) {
            result in
            
            switch result {
            case .failure(let error):
                self.buttonLogin.setActivity(false)
                Logger.app.debug("Login error. \(error.localizedDescription)")

                let alertController = UIAlertController(title: "FIDO2 Example", message: error.localizedDescription, preferredStyle: .alert)
                alertController.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
                
                DispatchQueue.main.async {
                    self.present(alertController, animated: true)
                }
            case .success(let value):
                self.accessToken = value
                
                self.fidoRegistration(url: tenantUrl, accessToken: value) { result in
                    self.buttonLogin.setActivity(false)
                    
                    switch result {
                    case .failure(let error):
                        Logger.app.debug("Login error. \(error.localizedDescription)")

                        let alertController = UIAlertController(title: "FIDO2 Example", message: error.localizedDescription, preferredStyle: .alert)
                        alertController.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
                        
                        DispatchQueue.main.async {
                            self.present(alertController, animated: true)
                        }
                    case .success(let value):
                        // Create the replying party string.
                        self.rpUrl = self.createRelyingPartyUrl(baseUrl: tenantUrl, registrationId: value)
                        DispatchQueue.main.async {
                            self.performSegue(withIdentifier: "ShowAttestation", sender: nil)
                        }
                    }
                }
            }
        }
    }
    
    private func login(url: String, clientId: String, username: String, password: String, completion: @escaping (Result<String, NetworkError>) -> Void) {
        
        guard let url = URL(string: "\(url)/v1.0/endpoint/default/token") else {
            completion(.failure(.badURL))
            return
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("application/x-www-form-urlencoded; charset=utf-8", forHTTPHeaderField: "Content-Type")
        
        let parameters = "client_id=\(clientId)&grant_type=password&username=\(username)&password=\(password)".addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!
        
        request.httpBody = parameters.data(using: .utf8)
        
        URLSession.shared.dataTask(with: request) { (data, response, error) in
            guard let data = data, let _ = response, error == nil else {
                completion(.failure(.general(message: error!.localizedDescription)))
                return
            }
            
            Logger.networking.info("HTTP response\n\(String(data: data, encoding: .utf8)!, privacy: .public)")
            do {
                guard let dictionary = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any], let value = dictionary["access_token"] as? String  else {
                    completion(.failure(.general(message: "\(String(data: data, encoding: .utf8) ?? "Invalid")")
                    ))
                    return
                }
                completion(.success(value))
            }
        }.resume()
    }
    
    private func fidoRegistration(url: String, accessToken: String, completion: @escaping (Result<String, NetworkError>) -> Void) {
        guard let url = URL(string: "\(url)/v2.0/factors/fido2/relyingparties") else {
            completion(.failure(.badURL))
            return
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        
        request.httpBody = "{\"origin\": \"\(url.host!)\"}".data(using: .utf8)
        
        URLSession.shared.dataTask(with: request) { (data, response, error) in
            guard let data = data, let _ = response, error == nil else {
                completion(.failure(.general(message: error!.localizedDescription)))
                return
            }
            
            Logger.networking.info("HTTP response\n\(String(data: data, encoding: .utf8)!, privacy: .public)")
            do {
                guard let dictionary = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any] else {
                    completion(.failure(.general(message: "\(String(data: data, encoding: .utf8) ?? "Invalid")")
                    ))
                    return
                }
                
                guard let fido = dictionary["fido2"] as? [Any], let value = fido.first as? [String: Any] else {
                   completion(.failure(.general(message: "The fido2 array held no elements.")))
                   return
                 }
                                
                guard let item = value.first(where: { $0.key == "id" }), let id = item.value as? String else {
                  completion(.failure(.general(message: "'id' not found in fido2 array.")))
                  return
                }
                
                completion(.success(id))
            }
        }.resume()
    }
    
    private func createRelyingPartyUrl(baseUrl: String, registrationId: String) -> String {
        return "\(baseUrl)/v2.0/factors/fido2/relyingparties/\(registrationId)"
    }
}
