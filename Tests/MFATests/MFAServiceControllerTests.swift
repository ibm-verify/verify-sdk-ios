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
        let registrationUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration")!
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
}
