//
// Copyright contributors to the IBM Verify Adaptive SDK for iOS project
//

import XCTest
@testable import Adaptive

class LocalMockAdaptiveTests: XCTestCase {
    var requiresResult: RequiresAssessmentResult?
    
    override func tearDown() {
        requiresResult = nil
       
        AdaptiveContext.shared.collectionService = mockCollectionService
        try? AdaptiveContext.shared.start()
    }
    
    // MARK: Assessment
    
    /// This test invokes the assessment func.
    func testAssessmentRandomly() {
        let sessionId = AdaptiveContext.shared.sessionId
        let mock = LocalMockAdaptive()
        mock.assessment(with: sessionId, evaluationContext: "login") { result in
        switch result {
            case .success(let assessmentResult):
                if let allowResult = assessmentResult as? AllowAssessmentResult {
                    print("Token \(allowResult.token)")
                }
                else if let requiresResult = assessmentResult as? RequiresAssessmentResult {
                    print("TransactionId \(requiresResult.transactionId)\nFactors \(requiresResult.factors)")
                }
                else if assessmentResult is DenyAssessmentResult {
                    print("Deny")
                }
                    
            case .failure(let error):
                print("Error \(error.localizedDescription)")
            }
        }
    }
    
    /// This test returns a deny result.
    func testAssessmentAllows() {
        let sessionId = AdaptiveContext.shared.sessionId
        let mock = LocalMockAdaptive(testType: .allow)
        mock.assessment(with: sessionId, evaluationContext: "login") { result in
        switch result {
            case .success(let assessmentResult):
                if assessmentResult is AllowAssessmentResult {
                    print("Allow")
                }
                    
            case .failure(let error):
                print("Error \(error.localizedDescription)")
                XCTFail()
            }
        }
    }
    
    /// This test returns a deny result.
    func testAssessmentDeny() {
        let sessionId = AdaptiveContext.shared.sessionId
        let mock = LocalMockAdaptive(testType: .deny)
        mock.assessment(with: sessionId, evaluationContext: "login") { result in
        switch result {
            case .success(let assessmentResult):
                if assessmentResult is DenyAssessmentResult {
                    print("Deny")
                }
                    
            case .failure(let error):
                print("Error \(error.localizedDescription)")
                XCTFail()
            }
        }
    }
    
    /// This test returns a requires result.
    func testAssessmentRequiresEnrolled() {
        let sessionId = AdaptiveContext.shared.sessionId
        let mock = LocalMockAdaptive(testType: .requiresEnrolled)
        mock.assessment(with: sessionId, evaluationContext: "login") { result in
        switch result {
            case .success(let assessmentResult):
                if assessmentResult is RequiresAssessmentResult, let hipster = assessmentResult as? RequiresAssessmentResult {
                    if hipster.factors.contains(where: ({$0.type == .totp })) {
                        print("Do something with One time passcode")
                    }
                    else if hipster.factors.contains(where: {($0.type == .password)}) {
                        print("Do something with username passcode.")
                    }
                    else if hipster.factors.contains(where: {($0.type == .fido2)}) {
                        print("Do something with FIDO")
                    }
                    print("Requires")
                }
                    
            case .failure(let error):
                print("Error \(error.localizedDescription)")
                XCTFail()
            }
        }
    }
    
    /// This test returns a requires result.
    func testAssessmentRequiresAllowed() {
        let sessionId = AdaptiveContext.shared.sessionId
        let mock = LocalMockAdaptive(testType: .requiresAllowed)
        mock.assessment(with: sessionId, evaluationContext: "login") { result in
        switch result {
            case .success(let assessmentResult):
                if assessmentResult is RequiresAssessmentResult, let hipster = assessmentResult as? RequiresAssessmentResult {
                    if hipster.factors.contains(where: ({$0.type == .totp })) {
                        print("Do something with One time passcode")
                    }
                    else if hipster.factors.contains(where: {($0.type == .password)}) {
                        print("Do something with username passcode.")
                    }
                    else if hipster.factors.contains(where: {($0.type == .fido2)}) {
                        print("Do something with FIDO")
                    }
                    print("Requires")
                }
                    
            case .failure(let error):
                print("Error \(error.localizedDescription)")
                XCTFail()
            }
        }
    }
    
    // MARK: Evaluation
    
    /// This test invokes the evaluation func.
    func testEvaluationRequiresAllowed() {
        AdaptiveContext.shared.collectionService = mockCollectionService
        try? AdaptiveContext.shared.start()
        
        let sessionId = AdaptiveContext.shared.sessionId
        let mock = LocalMockAdaptive(testType: .requiresAllowed)
        
        mock.assessment(with: sessionId, evaluationContext: "login") { result in
        switch result {
            case .success(let assessmentResult):
                if let value = assessmentResult as? RequiresAssessmentResult {
                    self.requiresResult = value
                }
            case .failure(let error):
                print("Error \(error.localizedDescription)")
            }
        }
        
        sleep(2)
        
        let evaluation = UsernamePasswordEvaluation(self.requiresResult!.transactionId, username: "usernmae", password: "password")
        
        mock.testType = .requiresEnrolled
        mock.evaluate(using: evaluation, evaluationContext: "login") { result in
            print("Evaluation result \(result)")
        }
    }
    
    /// This test invokes the evaluation func.
    func testEvaluationRequiresEnrolled() {
        AdaptiveContext.shared.collectionService = mockCollectionService
        try? AdaptiveContext.shared.start()
    
        let sessionId = AdaptiveContext.shared.sessionId
        let mock = LocalMockAdaptive(testType: .requiresEnrolled)
        
        mock.assessment(with: sessionId, evaluationContext: "login") { result in
        switch result {
            case .success(let assessmentResult):
                if let value = assessmentResult as? RequiresAssessmentResult {
                    self.requiresResult = value
                }
            case .failure(let error):
                print("Error \(error.localizedDescription)")
            }
        }
        
        sleep(2)
        
        let evaluation = UsernamePasswordEvaluation(self.requiresResult!.transactionId, username: "usernmae", password: "password")
        
        mock.testType = .allow
        mock.evaluate(using: evaluation, evaluationContext: "login") { result in
             print("Evaluation result \(result)")
        }
    }
    
    /// This test the QR code evaluation.
    func testEvaluationQrcode() {
        // Given
        let accessToken = """
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
        """
        
        // Where
        let result = QrCodeEvaluation(UUID().uuidString, accessToken: accessToken)
        
        // Then
        XCTAssertNotNil(result, "QR evaluation result was parsed successfully.")
    }
    
    /// This test the question evaluation.
    func testEvaluationQuestions() {
        // Given
        let answers = [
            "firstHouseStreet": "Somthing",
            "bestFriend": "Something",
            "mothersMaidenName": "Something"
        ]
        
        // Where
        let result = KnowledgeQuestionEvaluation(UUID().uuidString, answers: answers)
        
        // Then
        XCTAssertNotNil(result, "QR evaluation result was parsed successfully.")
    }
    
    /// This test returns a email otp generation result.
    func testEvaluationTOTP() {
        // Given
        let code = "1293"
        
        // Where
        let result = OneTimePasscodeEvaluation(UUID().uuidString, code: code, otp: .totp)
        
        // Then
        XCTAssertNotNil(result, "TOTP evaluation result was parsed successfully.")
    }
    
    /// This test returns a email otp generation result.
    func testEvaluationEmailOTP() {
        // Given
        let code = "1293"
        
        // Where
        let result = OneTimePasscodeEvaluation(UUID().uuidString, code: code, otp: .emailotp)
        
        // Then
        XCTAssertNotNil(result, "Email OTP evaluation result was parsed successfully.")
    }
    
    /// This test returns a sms otp generation result.
    func testEvaluationSmsOTP() {
        // Given
        let code = "1293"
        
        // Where
        let result = OneTimePasscodeEvaluation(UUID().uuidString, code: code, otp: .smsotp)
        
        // Then
        XCTAssertNotNil(result, "SMS OTP evaluation result was parsed successfully.")
    }
    
    
    // MARK: Generation
    /// This test returns a email otp generation result.
    func testGenerationEmailOTP() {
        let mock = LocalMockAdaptive(testType: .requiresEnrolled)
        let assessment = EnrolledFactor(type: .emailotp, id: UUID().uuidString, enabled: true, validated: true, attributes: [:])
        
        mock.generate(with: assessment.id, transactionId: UUID().uuidString, factor: assessment.type) { result in
        switch result {
            case .success(let generationResult):
                if let hipster = generationResult as? OtpGenerateResult {
                    print("OTP correlation identifier prefix: \(hipster.correlation)")
                }
                else {
                    print("Correlation not required on non one-time passcode factor types.")
                }
                    
            case .failure(let error):
                print("Error \(error.localizedDescription)")
                XCTFail()
            }
        }
    }
    
    /// This test returns a SMS otp generation result.
    func testGenerationSmsOTP() {
        let mock = LocalMockAdaptive(testType: .requiresEnrolled)
        let assessment = EnrolledFactor(type: .smsotp, id: UUID().uuidString, enabled: true, validated: true, attributes: [:])
        
        
        mock.generate(with: assessment.id, transactionId: UUID().uuidString, factor: assessment.type) { result in
        switch result {
            case .success(let generationResult):
                if let hipster = generationResult as? OtpGenerateResult {
                    print("OTP correlation identifier prefix: \(hipster.correlation)")
                }
                else {
                    print("Correlation not required on non one-time passcode factor types.")
                }
                    
            case .failure(let error):
                print("Error \(error.localizedDescription)")
                XCTFail()
            }
        }
    }
    
    /// This test returns a time otp (TOTP) generation result.
    func testGenerationTOTP() {
        let mock = LocalMockAdaptive(testType: .requiresEnrolled)
        let assessment = EnrolledFactor(type: .totp, id: UUID().uuidString, enabled: true, validated: true, attributes: [:])
        
        
        mock.generate(with: assessment.id, transactionId: UUID().uuidString, factor: assessment.type) { result in
        switch result {
            case .success(let generationResult):
                if let hipster = generationResult as? OtpGenerateResult {
                    print("OTP correlation identifier prefix: \(hipster.correlation)")
                }
                else {
                    print("Correlation not required on non one-time passcode factor types.")
                }
                    
            case .failure(let error):
                print("Error \(error.localizedDescription)")
                XCTFail()
            }
        }
    }
    
    /// This test returns a time otp (TOTP) generation result.
    func testGenerationTOTPFromJSON() {
        // Given
        let json = """
            { "correlation": "1293" }
        """
        
        // Where
        let result = try? JSONDecoder().decode(OtpGenerateResult.self, from: json.data(using: .utf8)!)
        
        // Then
        XCTAssertNotNil(result, "OTP generate result was parsed successfully.")
    }
    
    /// This test returns a time otp (TOTP) generation result.
    func testGenerationTOTPFromInit() {
        // Given
        let correlation = "1293"
        
        // Where
        let result = OtpGenerateResult(correlation)
        
        // Then
        XCTAssertNotNil(result, "OTP generate result was parsed successfully.")
    }
    
    /// This test returns a FIDO evaluation result.
    func testEvaluationFidoFromInit() {
        // Given, Where
        let result = FIDOEvaluation(UUID().uuidString, clientDataJSON: "proxy-sdk-external.rel.verify.ibmcloudsecurity.com", authenticatorData: "device1", userHandle: "handle1", signature: "VGhpcyBpcyBhIHNpZ25lZCBjaGFsbGVuZ2UK")
        
        
        // Then
        XCTAssertNotNil(result, "FIDO evaluation result was parsed successfully.")
    }
    
    /// This test returns a FIDO evaluation with optional result.
    func testEvaluationFidoFromInitOptional() {
        // Given, Where
        let result = FIDOEvaluation(UUID().uuidString, clientDataJSON: "",  authenticatorData: "device1", signature: "VGhpcyBpcyBhIHNpZ25lZCBjaGFsbGVuZ2UK")
        
        
        // Then
        XCTAssertNotNil(result, "FIDO evaluation result was parsed successfully.")
    }
    
    /// This test returns a knowledge generation result.
    func testGenerationQuestions() {
        let mock = LocalMockAdaptive(testType: .requiresEnrolled)
        let assessment = EnrolledFactor(type: .questions, id: UUID().uuidString, enabled: true, validated: true, attributes: [:])
        
        
        mock.generate(with: assessment.id, transactionId: UUID().uuidString, factor: assessment.type) { result in
        switch result {
            case .success(let generationResult):
                if let hipster = generationResult as? KnowledgeQuestionGenerateResult {
                    print("Knowledge questions count \(hipster.questions.count)")
                }
            case .failure(let error):
                print("Error \(error.localizedDescription)")
                XCTFail()
            }
        }
    }
    
    /// This test returns knowledge questions generation result.
    func testGenerationQuestionsFromJSON() {
        // Given
        let json = """
            {
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
        """
        
        // Where
        let result = try? JSONDecoder().decode(KnowledgeQuestionGenerateResult.self, from: json.data(using: .utf8)!)
        
        // Then
        XCTAssertNotNil(result, "Knowledge questions generate result was parsed successfully.")
    }
    
    /// This test returns knowledge questions generation result.
    func testGenerationQuestionsFromInit() {
        // Given
        let values = [
            QuestionInfo(questionKey: "firstHouseStreet", question: "What was the street name of the first house you ever lived in?"),
            QuestionInfo(questionKey: "bestFriend", question: "What was the street name of the first house you ever lived in?"),
            QuestionInfo(questionKey: "mothersMaidenName", question: "What is your mothers maiden name?")
        ]
        
        // Where
        let result = KnowledgeQuestionGenerateResult(values)
        
        // Then
        XCTAssertNotNil(result, "Knowledge questions generate result was parsed successfully.")
    }
    
    /// This test returns knowledge questions generation result.
    func testGenerationFIDOFromJSON() {
        // Given
        let json = """
            {
                "transactionId": "c44fa1c2-9eaf-4cdc-91c9-0c44c159c705",
                "fido": {
                    "rpId": "proxy-sdk-external.rel.verify.ibmcloudsecurity.com",
                    "timeout": 240000,
                    "challenge": "XH5-Q-Kpxdjdd1Fgt1nLmgElK25UxjqyydayQQk12wI",
                    "allowCredentials": [
                        {
                            "id": "z2cH5DQdqUrD-6Jtp8MTvzzierueIr4LZENLt5GOup6ap8Pwf07FKkOfVqzqPR9FlSnwuFjnVF-3z4p2Lq8qIqOJz40-FyZd6C9vRdsoz9ubFw8Hrxdnpm6RsAFN3U228DdXHhRVhgR8bcyKC7GN6Q",
                            "type": "public-key"
                        },
                        {
                            "id": "yZd6C9vRdsoz9ubFw8Hrxdnpm6RsAFN3U228DdXHhRVhgR8bcyKC7GN6Qz2cH5DQdqUrD-6Jtp8MTvzzierueIr4LZENLt5GOup6ap8Pwf07FKkOfVqzqPR9FlSnwuFjnVF-3z4p2Lq8qIqOJz40-F",
                            "type": "private-key"
                        }
                    ],
                    "extensions": {},
                    "userVerification": "preferred"
                }
            }
        """
        
        // Where
        let result = try? JSONDecoder().decode(FIDOGenerateResult.self, from: json.data(using: .utf8)!)
        
        // Then
        XCTAssertNotNil(result, "FIDO generate result was parsed successfully.")
    }
    
    /// This test returns knowledge questions generation result.
    func testGenerationFIDOFromJSONOptionals() {
        // Given
        let json = """
            {
                "transactionId": "c44fa1c2-9eaf-4cdc-91c9-0c44c159c705",
                "fido": {
                    "rpId": "proxy-sdk-external.rel.verify.ibmcloudsecurity.com",
                    "timeout": 240000,
                    "challenge": "XH5-Q-Kpxdjdd1Fgt1nLmgElK25UxjqyydayQQk12wI",
                    "extensions": {}
                }
            }
        """
        
        // Where
        let result = try? JSONDecoder().decode(FIDOGenerateResult.self, from: json.data(using: .utf8)!)
        
        // Then
        XCTAssertNotNil(result, "FIDO generate result was parsed successfully.")
    }
    
    /// This test returns FIDO generation result.
    func testGenerationFIDOFromInit() {
        // Given, Where
        let result = FIDOGenerateResult("proxy-sdk-external.rel.verify.ibmcloudsecurity.com", challenge: "XH5-Q-Kpxdjdd1Fgt1nLmgElK25UxjqyydayQQk12wI", userVerification: "preferred", timeout: 24000, allowCredentials: [FIDOCredential("z2cH5DQdqUrD-6Jtp8MTvzzierueIr4LZENLt5GOup6ap8Pwf07FKkOfVqzqPR9FlSnwuFjnVF-3z4p2Lq8qIqOJz40-FyZd6C9vRdsoz9ubFw8Hrxdnpm6RsAFN3U228DdXHhRVhgR8bcyKC7GN6Q", "public-type")])
        
        // Then
        XCTAssertNotNil(result, "FIDO generate result was parsed successfully.")
    }
    
    /// This test returns FIDO generation result.
    func testGenerationFIDOFromInitOptionals() {
        // Given, Where
        let result = FIDOGenerateResult("proxy-sdk-external.rel.verify.ibmcloudsecurity.com", challenge: "XH5-Q-Kpxdjdd1Fgt1nLmgElK25UxjqyydayQQk12wI", timeout: 24000)
        
        // Then
        XCTAssertNotNil(result, "FIDO generate result was parsed successfully.")
    }
    
    /// This test returns a otp generation result.
    func testGenerationVoid() {
        let mock = LocalMockAdaptive(testType: .requiresEnrolled)
        let assessment = EnrolledFactor(type: .password, id: UUID().uuidString, enabled: true, validated: true, attributes: [:])
        
        mock.generate(with: assessment.id, transactionId: UUID().uuidString, factor: assessment.type) { result in
        switch result {
            case .success(let generationResult):
                if let hipster = generationResult as? OtpGenerateResult {
                    print("OTP correlation identifier prefix: \(hipster.correlation)")
                }
                else {
                    print("Correlation not required on non one-time passcode factor types.")
                }
                    
            case .failure(let error):
                print("Error \(error.localizedDescription)")
                XCTFail()
            }
        }
    }
    
    // MARK: Coding Keys
    func testJSONCodingKeysIntInit() {
        // Given
        let value = 0
        
        // Where
        let result = JSONCodingKeys(intValue: value)
        
        // Then
        XCTAssertNotNil(result, "Coding key result was parsed successfully.")
    }
    
    func testJSONCodingKeysStringInit() {
        // Given
        let value = "hello world"
        
        // Where
        let result = JSONCodingKeys(stringValue: value)
        
        // Then
        XCTAssertNotNil(result, "Coding key result was parsed successfully.")
    }
    
    func testArrayDecodeArray() {
        // Given
        let value = """
            [
                "cat",
                "dog",
                "cow"
            ]
        """
        
        // Where
        let result = try? JSONDecoder().decode(Array<AnyDecodable>.self, from: value.data(using: .utf8)!)
        
        // Then
        XCTAssertNotNil(result, "Coding key result was parsed successfully.")
    }
}
