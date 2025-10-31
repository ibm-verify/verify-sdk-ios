//
// Copyright contributors to the IBM Verify Adaptive Sample App for iOS project
//

import UIKit
import Adaptive
import SafariServices

class MainViewController: UIViewController {

    @IBOutlet weak var buttonPerformAssessment: UIButton!
    @IBOutlet weak var buttonRegisterForFIDO: UIButton!
    
    let tag = 120011
    var safariViewController: SFSafariViewController?
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
        
        NotificationCenter.default.addObserver(forName: .safariDismissRegister, object: nil, queue: nil, using: { _ in
            self.buttonRegisterForFIDO.isHidden = true
            self.safariViewController!.dismiss(animated: true, completion: nil)
        })
        
        buttonPerformAssessment.layer.cornerRadius = 5
        
        // TODO: Assign your collection service
        //AdaptiveContext.shared.collectionService = TrusteerCollectionService()
        
        // Initiate the Trusteer collection process.
        do {
            try AdaptiveContext.shared.start()
        }
        catch let error {
            let alertController = UIAlertController(title: "Trusteer", message: error.localizedDescription, preferredStyle: .alert)
            alertController.addAction(UIAlertAction(title: "OK", style: .default, handler: { _ in
                self.buttonPerformAssessment.isEnabled = false
            }))
            
            DispatchQueue.main.async {
                self.present(alertController, animated: true)
            }
        }
        
        buttonRegisterForFIDO.isHidden = isFIDORegistered || accessToken == nil
    }
   
   
    @IBAction func onRegisterForFIDOClick(_ sender: UIButton) {
        guard let idToken = idToken, let userId = idToken["sub"] as? String else {
            return
        }
        
        let urlString = "\(baseUrl)/generations/fido?token=\(accessToken ?? "")&userId=\(userId)"
            
        // Transition to Safari to complete FIDO flow.
        if let url = URL(string: urlString) {
            print("FIDO registration: \(urlString)")
            safariViewController = SFSafariViewController(url: url)
            safariViewController!.delegate = self

            self.present(safariViewController!, animated: true)
        }
    }
    
    @IBAction func unwindToMain(sender: UIStoryboardSegue) {
        if let viewController = sender.source as? AssessmentResultDelegate {
            removeContainer()
            
            if let adaptiveResult = viewController.assessmentResult as? AllowAssessmentResult {
                createTokenContainer(adaptiveResult.token)
                saveToken(adaptiveResult.token)
                
                buttonRegisterForFIDO.isHidden = isFIDORegistered || accessToken == nil
            }
            
            if viewController.assessmentResult is DenyAssessmentResult {
                createDenyContainer()
            }
        }
    }
    
    func removeContainer() {
        if let stackView = self.view.viewWithTag(self.tag) as? UIStackView {
            stackView.subviews.forEach{ view in
                stackView.removeArrangedSubview(view)
            }
            stackView.removeFromSuperview()
        }
    }
    
    // MARK: Helper functions
    func createDenyContainer() {
        let stackView = UIStackView()
        stackView.translatesAutoresizingMaskIntoConstraints = false
        stackView.axis = .vertical
        stackView.distribution = .equalSpacing
        stackView.spacing = 16
        stackView.tag = self.tag
        
        // Add a title label to the Stackview
        let labelTitle = UILabel()
        labelTitle.text = "Denied!"
        labelTitle.font = UIFont.systemFont(ofSize: 24, weight: .semibold)
        stackView.addArrangedSubview(labelTitle)
        
        // Add a description label to the Stackview
        let labelDescription = UILabel()
        labelDescription.text = "Authentication was evaluated and denied."
        stackView.addArrangedSubview(labelDescription)
        
        self.view.addSubview(stackView)

        // Add constraints
        stackView.topAnchor.constraint(equalTo: view.topAnchor, constant: 128).isActive = true
        stackView.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 20).isActive = true
        stackView.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -20).isActive = true
    }
    
    func createTokenContainer(_ token: String) {
        let stackView = UIStackView()
        stackView.translatesAutoresizingMaskIntoConstraints = false
        stackView.axis = .vertical
        stackView.distribution = .equalSpacing
        stackView.spacing = 16
        stackView.tag = self.tag
        
        // Add a title label to the Stackview
        let labelTitle = UILabel()
        labelTitle.text = "Authenticated!"
        labelTitle.font = UIFont.systemFont(ofSize: 24, weight: .semibold)
        stackView.addArrangedSubview(labelTitle)
        
        // Add the text view to the Stackview
        let textView = UITextView()
        textView.textContainerInset = UIEdgeInsets(top: 10, left: 10, bottom: 10, right: 10)
        textView.text = token
        textView.font = UIFont(name: "Courier", size: 12)
        textView.isEditable = false
        textView.backgroundColor = .systemGray6
        textView.translatesAutoresizingMaskIntoConstraints = false
        
        let containerView = UIView()
        containerView.addSubview(textView)

        textView.leadingAnchor.constraint(equalTo: containerView.leadingAnchor).isActive = true
        textView.topAnchor.constraint(equalTo: containerView.topAnchor).isActive = true
        textView.trailingAnchor.constraint(equalTo: containerView.trailingAnchor).isActive = true
        textView.bottomAnchor.constraint(equalTo: containerView.bottomAnchor).isActive = true
        textView.heightAnchor.constraint(equalToConstant: 384).isActive = true
        
        stackView.addArrangedSubview(containerView)
        
        self.view.addSubview(stackView)

        // Add constraints
        stackView.topAnchor.constraint(equalTo: view.topAnchor, constant: 128).isActive = true
        stackView.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 20).isActive = true
        stackView.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -20).isActive = true
    }
}

extension MainViewController: SFSafariViewControllerDelegate {
    func safariViewControllerDidFinish(_ controller: SFSafariViewController) {
        print("Completed FIDO operation.")
    }
}
