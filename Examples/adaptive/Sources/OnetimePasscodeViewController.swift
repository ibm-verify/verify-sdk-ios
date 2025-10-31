//
// Copyright contributors to the IBM Verify Adaptive Sample App for iOS project
//

import Foundation
import UIKit
import Adaptive

class OnetimePasscodeViewController: UIViewController, AssessmentResultDelegate {
    @IBOutlet weak var buttonEvaluate: UIButton!
    @IBOutlet weak var textfieldOtp: UITextField!
    @IBOutlet weak var labelTitle: UILabel!
    
    var transactionId: String?
    var correlationId: String?
    var otp: OneTimePasscodeType = .emailotp
    var assessmentResult: AdaptiveResult?
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
        
        buttonEvaluate.layer.cornerRadius = 5
        textfieldOtp.layer.addSublayer(createBottomBorder(width: textfieldOtp.frame.width - 40, height: textfieldOtp.frame.height))
        
        if let prefix = correlationId {
            labelTitle.text! += " \(prefix)"
        }
        
        // Hides the keyboard
        textfieldOtp.delegate = self
    }
    
    // MARK: Control events
    
    @IBAction func onEvaluateClick(_ sender: UIButton) {
        guard let value = textfieldOtp.text, !value.isEmpty else {
            let alertController = UIAlertController(title: "Evaluation", message: "Code is empty.", preferredStyle: .alert)
            alertController.addAction(UIAlertAction(title: "OK", style: .default))
            self.present(alertController, animated: true)
            return
        }
        
        // Construct a new Otp evaluation instance.
        let evaluation = OneTimePasscodeEvaluation(transactionId!, code: value, otp: otp)
        
        buttonEvaluate.setActivity(true)
        
        // Attempt the evaluation of the username and password.
        AdaptiveService().evaluate(using: evaluation, evaluationContext: UUID().uuidString) { result in
            DispatchQueue.main.async {
                self.buttonEvaluate.setActivity(false)
                
                switch result {
                case .success(let assessmentResult):
                    self.assessmentResult = assessmentResult
                    
                    if assessmentResult is AllowAssessmentResult || assessmentResult is DenyAssessmentResult {
                        self.performSegue(withIdentifier: "UnwindOnetimePasscode", sender: self)
                    }
                    else {
                        self.performSegue(withIdentifier: "ShowSecondFactor", sender: self)
                    }
                case .failure(let error):
                    let alertController = UIAlertController(title: "Evaluation", message: error.localizedDescription, preferredStyle: .alert)
                    alertController.addAction(UIAlertAction(title: "OK", style: .default, handler: { _ in
                        self.assessmentResult = DenyAssessmentResult()
                        self.performSegue(withIdentifier: "UnwindOnetimePasscode", sender: self)
                    }))
                    self.present(alertController, animated: true)
                }
            }
        }
    }
}
