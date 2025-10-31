//
// Copyright contributors to the IBM Verify Adaptive Sample App for iOS project
//

import Foundation
import UIKit
import Adaptive

class SecondFactorViewController: UIViewController {
    var assessmentResult: RequiresAssessmentResult?
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // Create the available buttons for 2nd factor generation.
        guard let requiresAssessment = assessmentResult else {
            return
        }
        
        createButtonContainer(assessment: requiresAssessment)
    }
    
    override func prepare(for segue: UIStoryboardSegue, sender: Any?) {
        if let viewController = segue.destination as? PasswordViewController, let values = sender as? [String: String] {
            viewController.transactionId = values["transactionId"]
        }
        
        if let viewController = segue.destination as? KnowledgeQuestionsViewController, let values = sender as? [String: Any] {
            viewController.transactionId = values["transactionId"] as? String
            viewController.questions = values["questions"] as? [QuestionInfo]
        }
        
        if let viewController = segue.destination as? OnetimePasscodeViewController, let values = sender as? [String: Any] {
            viewController.transactionId = values["transactionId"] as? String
            viewController.correlationId = values["correlationId"] as? String
            
            if let otp = values["otp"] as? FactorType {
                switch otp {
                case .emailotp:
                    viewController.otp = .emailotp
                case .smsotp:
                    viewController.otp = .smsotp
                case .totp:
                    viewController.otp = .totp
                default:
                    viewController.otp = .emailotp
                }
            }
        }
    }
    
    // MARK: Support functions
    func createOtpActionHandler(with button: UIButton, enrolmentId: String, transactionId: String, factor: FactorType) ->
    UIAction {
        return UIAction(handler: { _ in
            button.setActivity(true)
            
            AdaptiveService().generate(with: enrolmentId, transactionId: transactionId, factor: factor) { result in
                DispatchQueue.main.async {
                    button.setActivity(false)
                    
                    switch result {
                    case .success(let generateResult):
                        if let result = generateResult as? OtpGenerateResult {
                            self.performSegue(withIdentifier: "ShowOnetimePasscode", sender: ["transactionId": transactionId, "correlationId": result.correlation, "otp": factor])
                        }
                        if generateResult is VoidGenerateResult {
                            self.performSegue(withIdentifier: "ShowPassword", sender: ["transactionId": transactionId])
                        }
                    case .failure(let error):
                        let alertController = UIAlertController(title: "Evaluation", message: error.localizedDescription, preferredStyle: .alert)
                        alertController.addAction(UIAlertAction(title: "OK", style: .default))
                        self.present(alertController, animated: true)
                    }
                }
            }
        })
    }
    
    func createKnowledgeActionHandler(with button: UIButton, enrolmentId: String, transactionId: String, factor: FactorType) ->
    UIAction {
        return UIAction(handler: { _ in
            button.setActivity(true)
            
            AdaptiveService().generate(with: enrolmentId, transactionId: transactionId, factor: factor) { result in
                DispatchQueue.main.async {
                    button.setActivity(false)
                    
                    switch result {
                    case .success(let generateResult):
                        if let result = generateResult as? KnowledgeQuestionGenerateResult {
                            self.performSegue(withIdentifier: "ShowKnowledgeQuestions", sender: ["transactionId": transactionId, "questions": result.questions])
                        }
                        if generateResult is VoidGenerateResult {
                            self.performSegue(withIdentifier: "ShowPassword", sender: ["transactionId": transactionId])
                        }
                    case .failure(let error):
                        let alertController = UIAlertController(title: "Evaluation", message: error.localizedDescription, preferredStyle: .alert)
                        alertController.addAction(UIAlertAction(title: "OK", style: .default))
                        self.present(alertController, animated: true)
                    }
                }
            }
        })
    }
    
    func createButtonContainer(assessment: RequiresAssessmentResult) {
        let stackView = UIStackView()
        stackView.translatesAutoresizingMaskIntoConstraints = false
        stackView.axis = .vertical
        stackView.distribution = .equalSpacing
        stackView.spacing = 16
        
        // Add a title label to the Stackview
        let labelTitle = UILabel()
        labelTitle.text = "Select a second factor method"
        stackView.addArrangedSubview(labelTitle)
        
        guard let factors = assessment.factors as? [EnrolledFactor] else {
            return
        }
        
        // Add buttons representing a factor
        factors.forEach { factor in
            if factor.type == .password {
                let button = createButton("Password")
                button.addAction(UIAction(handler: { _ in
                    self.performSegue(withIdentifier: "ShowPassword", sender: assessment.transactionId)
                }), for: .touchUpInside)
                
                stackView.addArrangedSubview(button)
            }
            if factor.type == .emailotp {
                let button = createButton("Email OTP")
                let action = createOtpActionHandler(with: button, enrolmentId: factor.id, transactionId: assessment.transactionId, factor: factor.type)
                button.addAction(action, for: .touchUpInside)
                
                stackView.addArrangedSubview(button)
            }
            if factor.type == .smsotp {
                let button = createButton("SMS OTP")
                let action = createOtpActionHandler(with: button, enrolmentId: factor.id, transactionId: assessment.transactionId, factor: factor.type)
                button.addAction(action, for: .touchUpInside)
                
                stackView.addArrangedSubview(button)
            }
            if factor.type == .totp {
                let button = createButton("Time OTP")
                let action = createOtpActionHandler(with: button, enrolmentId: factor.id, transactionId: assessment.transactionId, factor: factor.type)
                button.addAction(action, for: .touchUpInside)
                
                stackView.addArrangedSubview(button)
            }
            
            if factor.type == .questions {
                let button = createButton("Knowledge Questions")
                let action = createKnowledgeActionHandler(with: button, enrolmentId: factor.id, transactionId: assessment.transactionId, factor: factor.type)
                button.addAction(action, for: .touchUpInside)
                
                stackView.addArrangedSubview(button)
            }
            
            // TODO: Check for other factor types and add those buttons as well.
        }
        
        self.view.addSubview(stackView)

        // Add constraints
        stackView.topAnchor.constraint(equalTo: view.topAnchor, constant: 128).isActive = true
        stackView.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 20).isActive = true
        stackView.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -20).isActive = true
    }
}
