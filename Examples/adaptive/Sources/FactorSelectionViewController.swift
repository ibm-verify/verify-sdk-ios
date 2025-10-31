//
// Copyright contributors to the IBM Verify Adaptive Sample App for iOS project
//

import Foundation
import UIKit
import Adaptive
import SafariServices

class FactorSelectionViewController: UIViewController, AssessmentResultDelegate {
    var assessmentResult: AdaptiveResult?
    var safariViewController: SFSafariViewController?
    
    @IBOutlet weak var activity: UIActivityIndicatorView!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        NotificationCenter.default.addObserver(self, selector:#selector(safariDissmiss(_:)), name: .safariDismissLogin, object: nil)
        
        // Attempt to determine which factors are required.
        AdaptiveService().assessment(with: AdaptiveContext.shared.sessionId, evaluationContext: UUID().uuidString) { result in
            DispatchQueue.main.async {
                self.activity.stopAnimating()
                
                switch result {
                case .success(let assessmentResult):
                    if assessmentResult is RequiresAssessmentResult {
                        self.createButtonContainer(assessment: (assessmentResult as! RequiresAssessmentResult))
                    }
                    if assessmentResult is DenyAssessmentResult {
                        self.assessmentResult = assessmentResult
                        self.performSegue(withIdentifier: "UnwindFactorSelection", sender: self)
                    }
                case .failure(let error):
                    let alertController = UIAlertController(title: "Assessment", message: error.localizedDescription, preferredStyle: .alert)
                    alertController.addAction(UIAlertAction(title: "OK", style: .default))
                    self.present(alertController, animated: true)
                }
            }
        }
    }
    
    override func prepare(for segue: UIStoryboardSegue, sender: Any?) {
        if let viewController = segue.destination as? PasswordViewController, let transactionId = sender as? String {
            viewController.transactionId = transactionId
        }
    }
    
    // MARK: Support functions
    @objc func safariDissmiss(_ notification: Notification) {
        if let assessmentResult = notification.userInfo?["result"] as? AdaptiveResult {
            self.assessmentResult = assessmentResult
            self.performSegue(withIdentifier: "UnwindFactorSelection", sender: self)
            self.safariViewController?.dismiss(animated: true, completion: nil)
        }
    }
    
    func createButtonContainer(assessment: AdaptiveResult) {
        let stackView = UIStackView()
        stackView.translatesAutoresizingMaskIntoConstraints = false
        stackView.axis = .vertical
        stackView.distribution = .equalSpacing
        stackView.spacing = 16
        
        // Add a title label to the Stackview
        let labelTitle = UILabel()
        labelTitle.text = "Select a method to validate your account"
        stackView.addArrangedSubview(labelTitle)
        
        // Check if FIDO is registered.
        
        if let assessmentResult = assessment as? RequiresAssessmentResult {
            // Add buttons representing a factor
            assessmentResult.factors.forEach { factor in
                if factor.type == .password {
                    let button = createButton("Password")
                    button.addAction(UIAction(handler: { _ in
                        self.performSegue(withIdentifier: "ShowPassword", sender: assessmentResult.transactionId)
                    }), for: .touchUpInside)
                    
                    stackView.addArrangedSubview(button)
                }
                
                if factor.type == .qr {
                    let button = createButton("QR scan")
                    button.addAction(UIAction(handler: { _ in
                        print("Show the view controller to launch the camera to scan a QR code.")
                    }), for: .touchUpInside)
                    
                    stackView.addArrangedSubview(button)
                }
                    
                if factor.type == .fido2 && isFIDORegistered {
                    let button = createButton("FIDO")
                    button.addAction(UIAction(handler: { _ in
                        let urlString = "\(baseUrl)/evaluations/fido?transactionId=\(assessmentResult.transactionId)&sessionId=\(AdaptiveContext.shared.sessionId)"
                            
                        // Transition to Safari to complete FIDO flow.
                        if let url = URL(string: urlString) {
                            print("FIDO login: \(urlString)")
                            self.safariViewController = SFSafariViewController(url: url)
                            self.safariViewController!.delegate = self
                            self.present(self.safariViewController!, animated: true)
                        }
                    }), for: .touchUpInside)
                    
                    stackView.addArrangedSubview(button)
                }
            }
            
            self.view.addSubview(stackView)

            // Add constraints
            stackView.topAnchor.constraint(equalTo: view.topAnchor, constant: 128).isActive = true
            stackView.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 20).isActive = true
            stackView.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -20).isActive = true
        }
    }
}

extension FactorSelectionViewController: SFSafariViewControllerDelegate {
    func safariViewControllerDidFinish(_ controller: SFSafariViewController) {
    }
}
