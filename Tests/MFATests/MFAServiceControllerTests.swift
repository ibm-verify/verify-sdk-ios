//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import XCTest
@testable import MFA

class MFAServiceControllerTests: XCTestCase {
    
    let urlBase = "https://sdk.verify.ibm.com"
    
    override func setUp() {
        super.setUp()
        URLProtocol.registerClass(MockURLProtocol.self)
    }
    
    override func tearDown() {
        super.tearDown()
        URLProtocol.unregisterClass(MockURLProtocol.self)
    }
    
    /// Tests the initiation of the `MFAServiceController` with an on-premise authenticator.
    func testInitiateServiceForOnPremise() async throws {
        // Given
        let authenticator = try await OnPremiseAuthenticatorTests().testDecodingTest()
        
        // Where
        let controller = MFAServiceController(using: authenticator)
        
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let service = controller.initiate()
        XCTAssertNotNil(service)
    }
    
    /// Tests the initiation of the `MFAServiceController` with a cloud authenticator.
    func testInitiateServiceForCloud() async throws {
        // Given
        let authenticator = try await CloudAuthenticatorTests().testDecodingTest()
        
        // Where
        let controller = MFAServiceController(using: authenticator)
        
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let service = controller.initiate()
        XCTAssertNotNil(service)
    }
    
    /// Test the service nextTransaction via protocol for a cloud authenticator.
    func testNextTransactionServiceForCloud() async throws {
        // Given
        let verificationsUrl = URL(string: "\(urlBase)/v1.0/authenticators/verifications\(CloudAuthenticatorService.TransactionFilter.nextPending.rawValue)")!
        
        MockURLProtocol.urls[verificationsUrl] = MockHTTPResponse(response: HTTPURLResponse(url: verificationsUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.transaction")
        let authenticator = try await CloudAuthenticatorTests().testDecodingTest()
        
        // Where
        let controller = MFAServiceController(using: authenticator)
        
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let service = controller.initiate()
        XCTAssertNotNil(service)
        
        // Then
        let nextTransaction = try! await service.nextTransaction(with: nil)
        XCTAssertNotNil(nextTransaction)
        print(nextTransaction)
    }
    
    /// Test the service completeTransaction via protocol for a cloud authenticator.
    func testCompleteTransactionSuccessForCloud() async throws {
        // Given
        let verificationsUrl = URL(string: "\(urlBase)/v1.0/authenticators/verifications\(CloudAuthenticatorService.TransactionFilter.nextPending.rawValue)")!
        let postbackUrl = URL(string: "\(urlBase)/v1.0/authenticators/verifications/b1bd512f-094e-4792-a0f6-6b9c75f50466")!
        
        MockURLProtocol.urls[verificationsUrl] = MockHTTPResponse(response: HTTPURLResponse(url: verificationsUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.transaction")
        MockURLProtocol.urls[postbackUrl] = MockHTTPResponse(response: HTTPURLResponse(url: postbackUrl, statusCode: 204, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.transaction")
        
        let authenticator = try await CloudAuthenticatorTests().testDecodingTest()
        
        // Where
        let controller = MFAServiceController(using: authenticator)
        
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let service = controller.initiate()
        XCTAssertNotNil(service)
        
        // Then
        let _ = try await service.nextTransaction(with: nil)
        
        try await service.completeTransaction(action: .verify, signedData: "xyz")
        XCTAssert(true, "Transaction completed")
    }
    
    /// Call login via protocol for a cloud authenticator.
    func testPerformLoginSuccessForCloud() async throws {
        // Given
        let loginUrl = URL(string: "\(urlBase)/v2.0/factors/qr")!
        
        MockURLProtocol.urls[loginUrl] = MockHTTPResponse(response: HTTPURLResponse(url: loginUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.login")
        
        let authenticator = try await CloudAuthenticatorTests().testDecodingTest()
        
        // Where
        let controller = MFAServiceController(using: authenticator)
        
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let service = controller.initiate()
        XCTAssertNotNil(service)
        
        
        // Then
        try await service.login(using: loginUrl, code: "abc123")
        XCTAssert(true, "Transaction completed")
    }
    
    /// Call refresh via protocol for a cloud authenticator.
    func testRefreshTokenWithAccountNameAndPushToken() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?metadataInResponse=false")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.refresh")
        
        let authenticator = try await CloudAuthenticatorTests().testDecodingTest()
        
        // Where
        let controller = MFAServiceController(using: authenticator)
        
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let service = controller.initiate()
        XCTAssertNotNil(service)
        
        let token = try? await service.refreshToken(using: "def456", accountName: "Test", pushToken: "xyz098", additionalData: nil)
        
        // Then
        XCTAssertNotNil(token, "TokenInfo returned success.")
        XCTAssertEqual(token?.refreshToken, "d4e5f6")
        XCTAssertEqual(token?.accessToken, "a1b2c3")
    }
    
    // MARK: Authenticator properties
    
    func testAllFactorsWithBothFactors() async {
        // Given
        let authenticator = try! await CloudAuthenticatorTests().testDecodingTest(file: "cloud.authenticatorAllFactors")
        
        // When
        let factors = authenticator.enrolledFactors
        
        // Then
        XCTAssertEqual(factors.count, 2)
        XCTAssertTrue(factors.contains {
            if case .biometric(let f) = $0 {
                return f.id == "X0CF603F-AE9B-49CE-AD07-70F5777377DB"
            }
            else {
                return false
            }
        })
        
        XCTAssertTrue(factors.contains {
            if case .userPresence(let f) = $0 {
                return f.id == "F0CF603F-AE9B-49CE-AD07-70F5777377DB"
            }
            else {
                return false
            }
        })
    }
    
    func testAllFactorsWithOnlyBiometric() async {
        // Given
        let authenticator = try! await CloudAuthenticatorTests().testDecodingTest(file: "cloud.authenticatorBiometric")
        
        // When
        let factors = authenticator.enrolledFactors
        
        // Then
        XCTAssertEqual(factors.count, 1)
        XCTAssertTrue(factors.contains {
            if case .biometric(let f) = $0 {
                return f.id == "X0CF603F-AE9B-49CE-AD07-70F5777377DB"
            }
            else {
                return false
            }
        })
    }
    
    func testAllFactorsWithOnlyUserPresence() async {
        // Given
        let authenticator = try! await CloudAuthenticatorTests().testDecodingTest()
        
        // When
        let factors = authenticator.enrolledFactors
        
        // Then
        XCTAssertEqual(factors.count, 1)
        XCTAssertTrue(factors.contains {
            if case .userPresence(let f) = $0 {
                return f.id == "F0CF603F-AE9B-49CE-AD07-70F5777377DB"
            }
            else {
                return false
            }
        })
    }
    
    func testAllFactorsWithNoFactors() async {
        // Given
        let authenticator = try! await CloudAuthenticatorTests().testDecodingTest(file: "cloud.authenticatorNoFactors")
        
        // When
        let factors = authenticator.enrolledFactors
        
        // Then
        XCTAssertTrue(factors.isEmpty)
    }
    
    func testTransactionFactorMatchesBiometric() async {
        // Given
        let verificationsUrl = URL(string: "\(urlBase)/v1.0/authenticators/verifications\(CloudAuthenticatorService.TransactionFilter.nextPending.rawValue)")!
        
        MockURLProtocol.urls[verificationsUrl] = MockHTTPResponse(response: HTTPURLResponse(url: verificationsUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.transaction")
        
        let authenticator = try! await CloudAuthenticatorTests().testDecodingTest(file: "cloud.authenticatorBiometric")
        
        // Where
        let controller = MFAServiceController(using: authenticator)
        let service = controller.initiate() as! CloudAuthenticatorService
        let transaction = try! await service.nextTransaction()
        let factor = controller.transactionFactor(for: transaction.current!)
        
        guard case .biometric(let f)? = factor else {
            return XCTFail("Expected biometric factor")
        }
        
        XCTAssertEqual(f.id, "X0CF603F-AE9B-49CE-AD07-70F5777377DB")
    }
    
    func testTransactionFactorMatchesUserPresence() async {
        // Given
        let verificationsUrl = URL(string: "\(urlBase)/v1.0/authenticators/verifications\(CloudAuthenticatorService.TransactionFilter.nextPending.rawValue)")!
        
        MockURLProtocol.urls[verificationsUrl] = MockHTTPResponse(response: HTTPURLResponse(url: verificationsUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.transactionUserPresence")
        
        let authenticator = try! await CloudAuthenticatorTests().testDecodingTest()
        
        // Where
        let controller = MFAServiceController(using: authenticator)
        let service = controller.initiate() as! CloudAuthenticatorService
        let transaction = try! await service.nextTransaction()
        let factor = controller.transactionFactor(for: transaction.current!)
        
        guard case .userPresence(let f)? = factor else {
            return XCTFail("Expected user presence factor")
        }
        
        XCTAssertEqual(f.id, "F0CF603F-AE9B-49CE-AD07-70F5777377DB")
    }
    
    func testTransactionFactorReturnsNilForUnknownID() async {
        // Given
        let verificationsUrl = URL(string: "\(urlBase)/v1.0/authenticators/verifications\(CloudAuthenticatorService.TransactionFilter.nextPending.rawValue)")!
        
        MockURLProtocol.urls[verificationsUrl] = MockHTTPResponse(response: HTTPURLResponse(url: verificationsUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.transactionNoFactor")
        
        let authenticator = try! await CloudAuthenticatorTests().testDecodingTest(file: "cloud.authenticatorBiometric")
        
        // Where
        let controller = MFAServiceController(using: authenticator)
        let service = controller.initiate() as! CloudAuthenticatorService
        let transaction = try! await service.nextTransaction()
        let factor = controller.transactionFactor(for: transaction.current!)
        
        XCTAssertNil(factor)
    }
}
