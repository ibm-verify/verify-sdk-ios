//
// Copyright contributors to the IBM Verify Adaptive SDK for iOS project
//

import Foundation
@testable import Adaptive

/// An mock implementation of the `AdaptiveDelegate`.
class RemoteMockAdaptive : AdaptiveDelegate {
    let baseUrl = "http://192.168.1.17:3000"
    
    func assessment(with sessionId: String, evaluationContext: String, completion: @escaping (Result<AdaptiveResult, Error>) -> Void) {
        let url = URL(string: "\(baseUrl)/assessments")!
        let parameters = ["sessionId": sessionId, "evaluationContext": evaluationContext]
        let session = URLSession.shared
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        request.addValue("application/json", forHTTPHeaderField: "Accept")
        
        // Make sure we can parse the JSON body
        do {
            request.httpBody = try JSONSerialization.data(withJSONObject: parameters, options: .prettyPrinted)
        }
        catch let error {
            print(error.localizedDescription)
        }

        let task = session.dataTask(with: request as URLRequest, completionHandler: {
            data, response, error in

            guard error == nil else {
                return
            }

            guard let data = data else {
                return
            }
            
            // Create json object from data
            let result = try! JSONDecoder().decode(MockAdaptiveServiceResult.self, from: data)
            
            if result.status == AssessmentStatusType.requires {
                completion(.success(RequiresAssessmentResult(result.transactionId!, factors: result.factors!)))
            }
            else if result.status == AssessmentStatusType.allow {
                completion(.success(AllowAssessmentResult(result.token!)))
            }
            else if result.status == AssessmentStatusType.deny  {
                completion(.success(DenyAssessmentResult()))
            }
        })
        task.resume()
    }
    
    func evaluate(using response: FactorEvaluation, evaluationContext: String, completion: @escaping (Result<AdaptiveResult, Error>) -> Void) {
        var url: URL?
        var parameters = ["sessionId": AdaptiveContext.shared.sessionId, "evaluationContext": evaluationContext, "transactionId": response.transactionId]
        
        if let usernameEvaluation = response as? UsernamePasswordEvaluation {
            url = URL(string: "\(baseUrl)/evaluations/password")
            parameters.updateValue(usernameEvaluation.username, forKey: "username")
            parameters.updateValue(usernameEvaluation.password, forKey: "password")
        }
        
        let session = URLSession.shared
        var request = URLRequest(url: url!)
        request.httpMethod = "POST"
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        request.addValue("application/json", forHTTPHeaderField: "Accept")
        
        // Make sure we can parse the JSON body
        do {
            request.httpBody = try JSONSerialization.data(withJSONObject: parameters, options: .prettyPrinted)
        }
        catch let error {
            print(error.localizedDescription)
        }

        let task = session.dataTask(with: request as URLRequest, completionHandler: {
            data, response, error in

            guard error == nil else {
                completion(.failure(error!))
                return
            }

            guard let data = data else {
                completion(.failure(AdaptiveError(with: "No data present in response.")))
                return
            }
            
            print("Evaluate response body \(String(describing: String(data: data, encoding: .utf8)))")
            
            
            // Create json object from data
            if let error = try? JSONDecoder().decode(AdaptiveError.self, from: data) {
                completion(.failure(error))
                return
            }
            
            let result = try! JSONDecoder().decode(MockAdaptiveServiceResult.self, from: data)
            
            if result.status == AssessmentStatusType.requires {
                completion(.success(RequiresAssessmentResult(result.transactionId!, factors: result.factors!)))
            }
            else if result.status == AssessmentStatusType.allow {
                completion(.success(AllowAssessmentResult(result.token!)))
            }
            else if result.status == AssessmentStatusType.deny  {
                completion(.success(DenyAssessmentResult()))
            }
        })
        task.resume()
    }
    
    func generate(with enrolmentId: String, transactionId: String, factor: FactorType, completion: @escaping (Result<GenerateResult, Error>) -> Void) {
        
        let mock = LocalMockAdaptiveService(returnType: 0)
        mock.performGeneration(factor: factor) { result in
            
            switch factor {
            case .emailotp, .totp, .smsotp:
                completion(.success(OtpGenerateResult(result)))
            default:
                completion(.success(VoidGenerateResult()))
            }
        }
    }
}


/// The mock adaptive service.  This represents the proxy service between mobile apps and Ci.
class RemoteMockAdaptiveService {
    let allowJSON = """
        { "status": "allow",
            "token" : {
                "issued_at": "1420262924658",
                "scope": "READ",
                "application_name": "ce1e94a2-9c3e-42fa-a2c6-1ee01815476b",
                "refresh_token_issued_at": "1420262924658",
                "expires_in": "1799",
                "token_type": "BearerToken",
                "refresh_token": "fYACGW7OCPtCNDEnRSnqFlEgogboFPMm",
                "client_id": "5jUAdGv9pBouF0wOH5keAVI35GBtx3dT",
                "access_token": "2l4IQtZXbn5WBJdL6EF7uenOWRsi",
                "organization_name": "My Happy Place",
                "refresh_token_expires_in": "86399"
            }
        }
    """
    let denyJSON = """
        { "status": "deny" }
    """
    
    let requiresEnrolledJSON = """
    { "status": "requires",
       "transactionId": "\(UUID().uuidString)",
       "enrolledFactors": [{
          "id": "61e39f0a-836b-48fa-b4c9-cface6a3ef5a",
          "userId": "60300035KP",
          "type": "fido2",
          "created": "2020-06-15T02:51:49.131Z",
          "updated": "2020-06-15T03:15:18.896Z",
          "attempted": "2020-07-16T04:30:14.066Z",
          "enabled": true,
          "validated": true,
          "attributes": {
            "emailAddress": "email@email.com"
          }
        },
        {
          "id": "61e39f0a-836b-48fa-b4c9-cface6a3ef5a",
          "userId": "60300035KP",
          "type": "multiFactor",
          "created": "2020-06-15T02:51:49.131Z",
          "updated": "2020-06-15T03:15:18.896Z",
          "attempted": "2020-07-16T04:30:14.066Z",
          "enabled": true,
          "validated": true,
          "attributes": {
            "emailAddress": "email@email.com",
            "biometry": "face"
          }
        }
      ]
    }
    """
    
    let requiresAllowedJSON = """
    { "status": "requires",
       "transactionId": "\(UUID().uuidString)",
       "allowedFactors" : [{ "type": "qr" }, { "type": "fido2" }, { "type": "password" }]
    }
    """
    
    let assessmentResults: [String]
    var returnType: Int
    
    init(returnType: Int) {
        self.assessmentResults = [allowJSON, denyJSON, requiresEnrolledJSON, requiresAllowedJSON]
        self.returnType = returnType
    }
    
    func performAssessment(sessionId: String, evaluationContext: String, completion: @escaping (String) -> Void) {
        completion(assessmentResults[returnType])
    }
    
    func performEvaluation(transactionId: String, evaluationContext: String, completion: @escaping (String) -> Void) {
        completion(assessmentResults[returnType])
    }
    
    func performGeneration(factor: FactorType, completion: @escaping (String) -> Void) {
        switch factor {
        case .emailotp, .totp, .smsotp:
            completion(String(UUID().uuidString.prefix(6)))
        default:
            completion("")
        }
    }
}
