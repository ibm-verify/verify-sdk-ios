//
// Copyright contributors to the IBM Verify Adaptive Sample App for iOS project
//

import Foundation
import UIKit
import Adaptive

class KnowledgeQuestionsViewController: UIViewController, AssessmentResultDelegate {
    var transactionId: String?
    var correlationId: String?
    var assessmentResult: AdaptiveResult?
    var questions: [QuestionInfo]?
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
        
        // Create the available questions to display.
        guard let requiredQuestions = questions else {
            return
        }
        
       createTextfieldContainer(questions: requiredQuestions)
    }
    
    // MARK: Control events
    
    @objc func onEvaluateClick(_ sender: UIButton) {
        // Get the stackview
        let stackView = self.view.subviews.first {
            $0.isKind(of: UIStackView.self)
        }
        
        // Get the UITextField's from UIStackView
        let controls = stackView?.subviews.filter {
            $0.isKind(of: UITextField.self)
        }
        
        var answers = [String: String]()
        
        controls!.forEach { view in
            let control = view as! UITextField
            
            if let value = control.text, !value.isEmpty {
                answers[control.customIdentifier!] = value
            }
        }
        
        if answers.count == 0 {
            let alertController = UIAlertController(title: "Evaluation", message: "Knowledge answer is empty.", preferredStyle: .alert)
            alertController.addAction(UIAlertAction(title: "OK", style: .default))
            self.present(alertController, animated: true)
            return
        }
        
        // Construct a new question and answer evaluation instance.
        let evaluation = KnowledgeQuestionEvaluation(transactionId!, answers: answers)
        
        sender.setActivity(true)
        
        // Attempt the evaluation of the username and password.
        AdaptiveService().evaluate(using: evaluation, evaluationContext: UUID().uuidString) { result in
            DispatchQueue.main.async {
                sender.setActivity(false)
                
                switch result {
                case .success(let assessmentResult):
                    self.assessmentResult = assessmentResult
                    
                    if assessmentResult is AllowAssessmentResult || assessmentResult is DenyAssessmentResult {
                        self.performSegue(withIdentifier: "UnwindKnowledgeQuestions", sender: self)
                    }
                    else {
                        self.performSegue(withIdentifier: "ShowSecondFactor", sender: self)
                    }
                case .failure(let error):
                    let alertController = UIAlertController(title: "Evaluation", message: error.localizedDescription, preferredStyle: .alert)
                    alertController.addAction(UIAlertAction(title: "OK", style: .default, handler: { _ in
                        self.assessmentResult = DenyAssessmentResult()
                        self.performSegue(withIdentifier: "UnwindKnowledgeQuestions", sender: self)
                    }))
                    self.present(alertController, animated: true)
                }
            }
        }
    }
    
    func createTextfieldContainer(questions: [QuestionInfo]) {
        // Creates the UIStackView to  hold the question and anwsers.
        let stackView = UIStackView()
        stackView.translatesAutoresizingMaskIntoConstraints = false
        stackView.axis = .vertical
        stackView.distribution = .equalSpacing
        stackView.spacing = 16
        
        // Creates the title.
        let label = UILabel()
        label.text = "Answer \(questions.count) questions"
        stackView.addArrangedSubview(label)
        
        // Add label and text fields representing a question and anwser.
        questions.forEach { item in
            // Add a title label to the Stackview
            let labelQuestion = UILabel()
            labelQuestion.text = item.question
            labelQuestion.lineBreakMode = .byWordWrapping
            labelQuestion.numberOfLines = 0
            stackView.addArrangedSubview(labelQuestion)
             
            // Add a text field to the Stackview
            let textField = UITextField()
            textField.placeholder = "Enter answer"
            textField.borderStyle = .none
            textField.heightAnchor.constraint(equalToConstant: 64).isActive = true
            textField.customIdentifier = item.questionKey
            textField.layer.addSublayer(createBottomBorder(width: view.frame.width - 40, height: 64))
            
            // Hides the keybaord
            textField.delegate = self
            
            stackView.addArrangedSubview(textField)
        
        }
        
        // Create the button
        let button = createButton("Evaluate")
        button.addTarget(self, action: #selector(onEvaluateClick), for: .touchUpInside)
        stackView.addArrangedSubview(button)
        
        self.view.addSubview(stackView)

        // Add constraints
        stackView.topAnchor.constraint(equalTo: view.topAnchor, constant: 128).isActive = true
        stackView.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 20).isActive = true
        stackView.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -20).isActive = true
    }
}
