//
// Copyright contributors to the IBM Verify Adaptive SDK for iOS project
//

import Foundation
@testable import Adaptive

/// An mock implementation of the `AdaptiveDelegate`.
class LocalMockAdaptive : AdaptiveDelegate {
    var testType = MockAdaptiveTestType.random
    var returnType: Int
    
    init(testType: MockAdaptiveTestType = MockAdaptiveTestType.random) {
        self.testType = testType
        
        switch self.testType {
        case .allow, .deny, .requiresEnrolled, .requiresAllowed:
            self.returnType = self.testType.rawValue
        case .random:
            self.returnType = Int.random(in: 0...3)
        }
    }
    
    func assessment(with sessionId: String, evaluationContext: String, completion: @escaping (Result<AdaptiveResult, Error>) -> Void) {
        
        let mock = LocalMockAdaptiveService(returnType: returnType)
        mock.performAssessment(sessionId: sessionId, evaluationContext: evaluationContext) { result in
            // Descode the JSON string
            let adaptiveResult = try! JSONDecoder().decode(MockAdaptiveServiceResult.self, from: Data(result.utf8))
            
            if adaptiveResult.status == AssessmentStatusType.requires {
                
                // Convert the factors array to an [Factor].
//                let factors = adaptiveResult.factors?.map( { Factor(value: $0) }).compactMap( {$0} )
                completion(.success(RequiresAssessmentResult(adaptiveResult.transactionId!, factors: adaptiveResult.factors!)))
            }
            else if adaptiveResult.status == AssessmentStatusType.allow {
                completion(.success(AllowAssessmentResult(adaptiveResult.token!)))
            }
            else if adaptiveResult.status == AssessmentStatusType.deny  {
                completion(.success(DenyAssessmentResult()))
            }
        }
    }
    
    func evaluate(using response: FactorEvaluation, evaluationContext: String, completion: @escaping (Result<AdaptiveResult, Error>) -> Void) {
        let mock = LocalMockAdaptiveService(returnType: returnType)
        mock.performEvaluation(transactionId: response.transactionId, evaluationContext: evaluationContext) { result in
            // Descode the JSON string
            let adaptiveResult = try! JSONDecoder().decode(MockAdaptiveServiceResult.self, from: Data(result.utf8))
            
            if adaptiveResult.status == AssessmentStatusType.requires {
                completion(.success(RequiresAssessmentResult(adaptiveResult.transactionId!, factors: adaptiveResult.factors!)))
            }
            else if adaptiveResult.status == AssessmentStatusType.allow {
                completion(.success(AllowAssessmentResult(adaptiveResult.token!)))
            }
            else if adaptiveResult.status == AssessmentStatusType.deny {
                completion(.success(DenyAssessmentResult()))
            }
        }
    }
    
    func generate(with enrolmentId: String, transactionId: String, factor: FactorType, completion: @escaping (Result<GenerateResult, Error>) -> Void) {
        
        let mock = LocalMockAdaptiveService(returnType: 0)
        mock.performGeneration(factor: factor) { result in
            
            switch factor{
            case .emailotp, .totp, .smsotp:
                completion(.success(OtpGenerateResult(result)))
            case .questions:
                completion(.success(KnowledgeQuestionGenerateResult([QuestionInfo(questionKey: "firstHouseStreet", question: "What was the street name of the first house you ever lived in?"), QuestionInfo(questionKey: "bestFriend", question: "What is the first name of your best friend?"), QuestionInfo(questionKey: "mothersMaidenName", question: "What is your mothers maiden name?")])))
            default:
                completion(.success(VoidGenerateResult()))
            }
        }
    }
}


/// The mock adaptive service.  This represents the proxy service between mobile apps and Ci.
class LocalMockAdaptiveService {
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
    {
        "status": "requires",
        "transactionId": "\(UUID().uuidString)",
        "enrolledFactors": [{
            "id": "61e39f0a-836b-48fa-b4c9-cface6a3ef5a",
            "userId": "60300035KP",
            "type": "multifactor",
            "created": "2020-06-15T02:51:49.131Z",
            "updated": "2020-06-15T03:15:18.896Z",
            "attempted": "2020-07-16T04:30:14.066Z",
            "enabled": true,
            "validated": true,
            "attributes": {
                "emailAddress": "email@email.com",
                "biometry": "face"
            }
        },
        {
            "id": "98a3a409-c64e-491d-872b-558c1ad645fc",
            "userId": "60300035KP",
            "type": "emailotp",
            "created": "2020-11-17T03:26:05.194Z",
            "updated": "2020-11-17T03:26:22.872Z",
            "attempted": "2020-11-19T01:14:54.416Z",
            "enabled": true,
            "validated": true,
            "attributes":{
                "emailAddress": "testuser2@cse-bank.net"
            }
        },
        {
            "id":"d4bb0e9d-9821-4ac5-a835-16117f190d38",
            "userId":"6020007JDE",
            "type":"questions",
            "attributes":{
                "questions": [{
                    "questionKey": "firstHouseStreet",
                    "question": "What was the street name of the first house you ever lived in?"
                },
                {
                    "questionKey": "bestFriend",
                    "question": "What is the first name of your best friend?"
                },
                {
                    "questionKey": "mothersMaidenName",
                    "question": "What is your mothers maiden name?"
                }]
            }
        }]
    }
    """
    
    let requiresAllowedJSON = """
    {
        "status": "requires",
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
