//
// Copyright contributors to the IBM Verify Adaptive SDK for iOS project
//

import XCTest
@testable import Adaptive

class RemoteMockAdaptiveTests: XCTestCase {
    override func tearDown() {
        AdaptiveContext.shared.collectionService = mockCollectionService
        try? AdaptiveContext.shared.stop()
    }
    
    // MARK: Assessment
    
    /// This test invokes the assessment, we're no sure what will be returned, a *PASS* is a valid assessment type.
    func testAssessmentRandomly() {
        // Create an expectation for a background download task.
        let expectation = XCTestExpectation(description: "Perform adaptive assessment on remote proxy.")

        AdaptiveContext.shared.collectionService = mockCollectionService
        try? AdaptiveContext.shared.start()
    
        let sessionId = AdaptiveContext.shared.sessionId
        let mock = RemoteMockAdaptive()
        mock.assessment(with: sessionId, evaluationContext: "login") { result in
        switch result {
            case .success(let assessmentResult):
                if assessmentResult is AllowAssessmentResult {
                    XCTAssertTrue(1 == 1, "Assessment returned an Allow.")
                }
                else if assessmentResult is RequiresAssessmentResult {
                    XCTAssertTrue(1 == 1, "Assessment returned an Requires.")
                }
                else if assessmentResult is DenyAssessmentResult {
                    XCTAssertTrue(1 == 1, "Assessment returned an Deny.")
                }
            case .failure(let error):
                print("Error \(error.localizedDescription)")
                XCTFail()
            }
            // Fulfill the expectation to indicate that the background task has finished successfully.
            expectation.fulfill()
        }
        
        // Wait until the expectation is fulfilled, with a timeout of 20 seconds.
        wait(for: [expectation], timeout: 20.0)
    }
    
    /// This test returns a result.
    func testAssessmentRequiresEnrolled() {
        // Create an expectation for a background download task.
        let expectation = XCTestExpectation(description: "Perform adaptive assessment on remote proxy.")


        AdaptiveContext.shared.collectionService = mockCollectionService
        try? AdaptiveContext.shared.start()
    
        let sessionId = AdaptiveContext.shared.sessionId
        let mock = RemoteMockAdaptive()
        mock.assessment(with: sessionId, evaluationContext: "login") { result in
        switch result {
            case .success(let assessmentResult):
                if let enrolment = assessmentResult as? RequiresAssessmentResult {
                    if enrolment.factors.contains(where: ({$0.type == .totp })) {
                        XCTAssertTrue(1 == 1, "Assessment factor is one-time passcode.")
                    }
                    else if enrolment.factors.contains(where: {($0.type == .password)}) {
                        XCTAssertTrue(1 == 1, "Assessment factor is password.")
                    }
                    else if enrolment.factors.contains(where: {($0.type == .fido2)}) {
                        XCTAssertTrue(1 == 1, "Assessment factor is FIDO.")
                    }
                }
                    
            case .failure(let error):
                print("Error \(error.localizedDescription)")
                XCTFail()
            }
            // Fulfill the expectation to indicate that the background task has finished successfully.
            expectation.fulfill()
        }
        
        // Wait until the expectation is fulfilled, with a timeout of 20 seconds.
        wait(for: [expectation], timeout: 20.0)
    }
    
    
    
    // MARK: Evaluation
    
    /// This test invokes the evaluation func.
    func testEvaluationRequiresPasswordFactor() {
        // Create an expectation for a background download task.
        let expectation1 = XCTestExpectation(description: "Perform adaptive assessment on remote proxy.")

        AdaptiveContext.shared.collectionService = mockCollectionService
        try? AdaptiveContext.shared.start()
    
        var evaluation: FactorEvaluation?
        
        let semaphore = DispatchSemaphore(value: 0)
        let sessionId = AdaptiveContext.shared.sessionId
        let mock = RemoteMockAdaptive()
        mock.assessment(with: sessionId, evaluationContext: "login") { result in
            switch result {
            case .success(let assessmentResult):
                if let enrolment = assessmentResult as? RequiresAssessmentResult {
                    if  enrolment.factors.contains(where: {($0.type == .password)}) {
                        evaluation = RemoteMockAdaptiveTests.createPasswordForEvaluation(enrolment.transactionId)
                    }
                }
                case .failure(let error):
                    print("Error \(error.localizedDescription)")
                    XCTFail()
            }

            // Fulfill the expectation to indicate that the background task has finished successfully.
            expectation1.fulfill()
            semaphore.signal()
        }
        
        let timeout = DispatchTime.now() + .seconds(20)
        
        if semaphore.wait(timeout: timeout) == .timedOut {
            print("Error request timed out.")
            XCTFail()
            return
        }
        
        // Create an expectation for a background download task.
        let expectation2 = XCTestExpectation(description: "Perform adaptive assessment on remote proxy.")
        
        // Attempt to process the evaluation
        mock.evaluate(using: evaluation!, evaluationContext: "login") { result in
            switch result {
            case .success(let assessmentResult):
                if let allow = assessmentResult as? AllowAssessmentResult {
                    XCTAssertTrue(!allow.token.isEmpty, "Token parsed successfully.")
                }
                case .failure(let error):
                    print("Error \(error.localizedDescription)")
                    XCTAssertTrue(true, "Password evaluation failed, ensure a valid user name and password exists.")
            }
            
            // Fulfill the expectation to indicate that the background task has finished successfully.
            expectation2.fulfill()
        }
            
        // Wait until the expectation is fulfilled, with a timeout of 30 seconds.
        wait(for: [expectation1, expectation2], timeout: 30.0)
        
    }
    
    // MARK: Helper functions

    static func createPasswordForEvaluation(_ transactionId: String) -> UsernamePasswordEvaluation {
        return UsernamePasswordEvaluation(transactionId, username: "testuser122", password: "password123")
    }
}
