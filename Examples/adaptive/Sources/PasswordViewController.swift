//
// Copyright contributors to the IBM Verify Adaptive Sample App for iOS project
//

import Foundation
import UIKit
import Adaptive

class PasswordViewController: UIViewController, AssessmentResultDelegate {
    @IBOutlet weak var textfieldUsername: UITextField!
    @IBOutlet weak var textfieldPassword: UITextField!
    @IBOutlet weak var buttonEvaluate: UIButton!
    
    var transactionId: String?
    var assessmentResult: AdaptiveResult?
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
        
        buttonEvaluate.layer.cornerRadius = 5
        textfieldUsername.layer.addSublayer(createBottomBorder(width: textfieldUsername.frame.width - 40, height: textfieldUsername.frame.height))
        textfieldPassword.layer.addSublayer(createBottomBorder(width: textfieldPassword.frame.width - 40, height: textfieldPassword.frame.height))
        textfieldUsername.becomeFirstResponder()
        
        // Hides the keyboard
        textfieldUsername.delegate = self
        textfieldPassword.delegate = self
    }
    
    override func prepare(for segue: UIStoryboardSegue, sender: Any?) {
        if let viewController = segue.destination as? SecondFactorViewController, let requiresAssessmentResult = self.assessmentResult as? RequiresAssessmentResult {
            viewController.assessmentResult = requiresAssessmentResult
        }
    }
    
    // MARK: Control events
    
    @IBAction func onEvaluateClick(_ sender: UIButton) {
        guard let username = textfieldUsername.text, !username.isEmpty else {
            let alertController = UIAlertController(title: "Evaluation", message: "Username is empty.", preferredStyle: .alert)
            alertController.addAction(UIAlertAction(title: "OK", style: .default))
            self.present(alertController, animated: true)
            return
        }
        
        guard let password = textfieldPassword.text, !password.isEmpty else {
            let alertController = UIAlertController(title: "Evaluation", message: "Password is empty.", preferredStyle: .alert)
            alertController.addAction(UIAlertAction(title: "OK", style: .default))
            self.present(alertController, animated: true)
            return
        }
        
        // Construct a new UsernamePassword evaluation instance.
        let evaluation = UsernamePasswordEvaluation(transactionId!, username: username, password: password)
        
        buttonEvaluate.setActivity(true)
        
        // Attempt the evaluation of the username and password.
        AdaptiveService().evaluate(using: evaluation, evaluationContext: UUID().uuidString) { result in
            DispatchQueue.main.async {
                self.buttonEvaluate.setActivity(false)
                
                switch result {
                case .success(let assessmentResult):
                    self.assessmentResult = assessmentResult
                    
                    if assessmentResult is AllowAssessmentResult || assessmentResult is DenyAssessmentResult {
                        self.performSegue(withIdentifier: "UnwindUsernamePassword", sender: self)
                    }
                    else {
                        self.performSegue(withIdentifier: "ShowSecondFactor", sender: self)
                    }
                case .failure(let error):
                    let alertController = UIAlertController(title: "Evaluation", message: error.localizedDescription, preferredStyle: .alert)
                    alertController.addAction(UIAlertAction(title: "OK", style: .default))
                    self.present(alertController, animated: true)
                }
            }
        }
    }
}
