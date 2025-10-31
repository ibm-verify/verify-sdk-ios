//
// Copyright contributors to the IBM Verify Adaptive Sample App for iOS project
//

import Adaptive
import Foundation

/// This delegate is used to pass the `AdaptiveResult` between `UIViewController`.
protocol AssessmentResultDelegate {
    var assessmentResult: AdaptiveResult? {
        get
        set
    }
}

public class AdaptiveService: NSObject, AdaptiveDelegate {
    public func assessment(with sessionId: String, evaluationContext: String, completion: @escaping (Result<AdaptiveResult, Error>) -> Void) {
        let url = URL(string: "\(baseUrl)/assessments")!
        let parameters = ["sessionId": AdaptiveContext.shared.sessionId]
        let session = URLSession(configuration: .default, delegate: self, delegateQueue: nil)
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        request.addValue("application/json", forHTTPHeaderField: "Accept")
        
        // Make sure we can parse the JSON body
        do {
            request.httpBody = try JSONSerialization.data(withJSONObject: parameters, options: .prettyPrinted)
            print("** Assessment Request **\n\(String(describing: String(data: request.httpBody!, encoding: .utf8)))")
        }
        catch let error {
            completion(.failure(error))
        }

        let task = session.dataTask(with: request, completionHandler: {
            data, response, error in

            guard error == nil else {
                completion(.failure(error!))
                return
            }

            guard let data = data else {
                completion(.failure(CocoaError.init(CocoaError.coderInvalidValue)))
                return
            }
            
            print("** Assessment Result **\n\(String(describing: String(data: data, encoding: .utf8)))")
            
            do {
                // Create json object from data
                let result = try JSONDecoder().decode(AdaptiveServiceResult.self, from: data)
                
                if result.status == AssessmentStatusType.requires {
                    completion(.success(RequiresAssessmentResult(result.transactionId!, factors: result.factors!)))
                }
                else if result.status == AssessmentStatusType.allow {
                    completion(.success(AllowAssessmentResult(result.token!)))
                }
                else if result.status == AssessmentStatusType.deny  {
                    completion(.success(DenyAssessmentResult()))
                }
            }
            catch let error {
                completion(.failure(error))
            }
        })
        task.resume()
    }
    
    public func generate(with enrolmentId: String, transactionId: String, factor: FactorType, completion: @escaping (Result<GenerateResult, Error>) -> Void) {
        // Using the factor.rawValue assumes the endpoint is of the same name i.e generations/emailotp
        let url = URL(string: "\(baseUrl)/generations/\(factor.rawValue)")!
        let parameters = ["sessionId": AdaptiveContext.shared.sessionId, "transactionId": transactionId, "enrollmentId": enrolmentId, "type": factor.rawValue]
        
        let session = URLSession(configuration: .default, delegate: self, delegateQueue: nil)
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        request.addValue("application/json", forHTTPHeaderField: "Accept")
        
        // Make sure we can parse the JSON body
        do {
            request.httpBody = try JSONSerialization.data(withJSONObject: parameters, options: .prettyPrinted)
            print("** Generate Request **\n\(String(describing: String(data: request.httpBody!, encoding: .utf8)))")
        }
        catch let error {
            completion(.failure(error))
        }
        
        let task = session.dataTask(with: request, completionHandler: {
            data, response, error in

            guard error == nil else {
                completion(.failure(error!))
                return
            }

            guard let data = data else {
                completion(.failure(CocoaError.init(CocoaError.coderInvalidValue)))
                return
            }
            
            print("** Generate Result **\n\(String(describing: String(data: data, encoding: .utf8)))")
            
            // Attempt to parse the JSON into one of the know generator results currently supported (OTP and knowledge questions)
            
            // Create json object from data
            if let result = try? JSONDecoder().decode(OtpGenerateResult.self, from: data) {
                completion(.success(result))
            }
            else if let result = try? JSONDecoder().decode(KnowledgeQuestionGenerateResult.self, from: data) {
                completion(.success(result))
            }
            else {
                completion(.success(VoidGenerateResult()))
            }
        })
        task.resume()
    }
    
    public func evaluate(using response: FactorEvaluation, evaluationContext: String, completion: @escaping (Result<AdaptiveResult, Error>) -> Void) {
        var url: URL?
        var parameters:[String: Any] = ["sessionId": AdaptiveContext.shared.sessionId, "transactionId": response.transactionId]
        
        if let evaluation = response as? UsernamePasswordEvaluation {
            url = URL(string: "\(baseUrl)/evaluations/password")
            parameters.updateValue(evaluation.username, forKey: "username")
            parameters.updateValue(evaluation.password, forKey: "password")
        }
        
        if let evaluation = response as? OneTimePasscodeEvaluation {
            if evaluation.otp == .totp {
                url = URL(string: "\(baseUrl)/evaluations/totp")
            }
            else if evaluation.otp == .smsotp {
                url = URL(string: "\(baseUrl)/evaluations/smsotp")
            }
            else {
                url = URL(string: "\(baseUrl)/evaluations/emailotp")
            }
            
            parameters.updateValue(evaluation.code, forKey: "otp")
        }
        
        if let evaluation = response as? KnowledgeQuestionEvaluation {
            url = URL(string: "\(baseUrl)/evaluations/questions")
            
            // Convert the dictionary of anwsers.
            var values = [[String: String]]()
            
            evaluation.answers.forEach {
                values.append(["questionKey": $0.key, "answer": $0.value])
            }
           
            parameters["questions"] = values
        }
        
        let session = URLSession(configuration: .default, delegate: self, delegateQueue: nil)
        var request = URLRequest(url: url!)
        request.httpMethod = "POST"
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        request.addValue("application/json", forHTTPHeaderField: "Accept")
        
        // Make sure we can parse the JSON body
        do {
            request.httpBody = try JSONSerialization.data(withJSONObject: parameters, options: .withoutEscapingSlashes)
            print("** Evaluate Request **\n\(String(describing: String(data: request.httpBody!, encoding: .utf8)))")
            
        }
        catch let error {
            completion(.failure(error))
        }
        
        let task = session.dataTask(with: request, completionHandler: {
            data, response, error in

            guard error == nil else {
                completion(.failure(error!))
                return
            }

            guard let data = data else {
                completion(.failure(CocoaError.init(CocoaError.coderInvalidValue)))
                return
            }
            
            print("** Evaluate Result **\n\(String(describing: String(data: data, encoding: .utf8)))")
            
            do {
                // Create json object from data
                let result = try JSONDecoder().decode(AdaptiveServiceResult.self, from: data)
            
                if result.status == AssessmentStatusType.requires {
                    completion(.success(RequiresAssessmentResult(result.transactionId!, factors: result.factors!)))
                }
                else if result.status == AssessmentStatusType.allow {
                    completion(.success(AllowAssessmentResult(result.token!)))
                }
                else if result.status == AssessmentStatusType.deny  {
                    completion(.success(DenyAssessmentResult()))
                }
            }
            catch let error {
                completion(.failure(error))
            }
        })
        task.resume()
    }
}

extension AdaptiveService: URLSessionDelegate {
    public func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        completionHandler(.useCredential, URLCredential(trust: serverTrust))
    }
}
