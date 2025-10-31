//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import XCTest
import Authentication
import Core
import CryptoKit
@testable import MFA

class CloudAuthenticatorServiceTest: XCTestCase {

    let urlBase = "https://sdk.verify.ibm.com"
    
    override func setUp() {
        super.setUp()
        URLProtocol.registerClass(MockURLProtocol.self)
    }

    override func tearDown() {
        super.tearDown()
        URLProtocol.unregisterClass(MockURLProtocol.self)
    }
    
    /// Attempts to refresh the access token for an authenticator with an invalid pinned certificate.
    func testCertificateTrustFailedWithRefresh() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.refresh")
        
        let publicKeyCertificate = "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"
        
        let pinnedCertificate = PinnedCertificateDelegate(with: publicKeyCertificate)
        
        // Where
        let service = CloudAuthenticatorService(with: "abc123", refreshUri: registrationUrl, transactionUri: URL(string: "\(urlBase)/v1.0/")!, authenticatorId: UUID().uuidString, certificateTrust: pinnedCertificate)
        
        // Then
        do {
            let _ = try await service.refreshToken(using: "def456")
        }
        catch let error {
            XCTAssert(error is URLError)
        }
    }

    /// Attempts to refresh the access token for an authenticator
    func testRefreshToken() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.refresh")
        
        // Where
        let service = CloudAuthenticatorService(with: "abc123", refreshUri: registrationUrl, transactionUri: URL(string: "\(urlBase)/v1.0/")!, authenticatorId: UUID().uuidString)
        let token = try? await service.refreshToken(using: "def456")
        
        
        // Then
        XCTAssertNotNil(token, "TokenInfo returned success.")
        XCTAssertEqual(token?.refreshToken, "d4e5f6")
        XCTAssertEqual(token?.accessToken, "a1b2c3")
    }
    
    /// Attempts to refresh the access token for an authenticator
    func testRefreshTokenWithAccountNameAndPushToken() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.refresh")
        
        // Where
        let service = CloudAuthenticatorService(with: "abc123", refreshUri: registrationUrl, transactionUri: URL(string: "\(urlBase)/v1.0/")!, authenticatorId: UUID().uuidString)
        let token = try? await service.refreshToken(using: "def456", accountName: "Test", pushToken: "xyz098")
        
        let accessToken = await service.accessToken
        
        // Then
        XCTAssertNotNil(token, "TokenInfo returned success.")
        XCTAssertEqual("a1b2c3", accessToken)
        XCTAssertEqual(token?.refreshToken, "d4e5f6")
        XCTAssertEqual(token?.accessToken, "a1b2c3")
    }
    
    /// Call nextTransaction by a transaction identifier.
    func testNextTransactionWithID() async throws {
        // Given
        let transactionID = "b1bd512f-094e-4792-a0f6-6b9c75f50466"
        let allowedCharacterSet = CharacterSet(charactersIn: "\"").inverted
        let queryString = String(format: "\(CloudAuthenticatorService.TransactionFilter.pendingByIdentifier.rawValue)", transactionID)
        let verificationsUrl = URL(string: "\(urlBase)/v1.0/authenticators/verifications/\(queryString.addingPercentEncoding(withAllowedCharacters: allowedCharacterSet)!)")!
        let transactionUrl = URL(string: "\(urlBase)/v1.0/authenticators/verifications")!
        
        MockURLProtocol.urls[verificationsUrl] = MockHTTPResponse(response: HTTPURLResponse(url: verificationsUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.transaction")
        
        // Where
        let service = CloudAuthenticatorService(with: "abc123", refreshUri: URL(string: "\(urlBase)/v1.0/")!, transactionUri: transactionUrl, authenticatorId: UUID().uuidString)
        
        let result = try await service.nextTransaction(with: transactionID)
        
        // Then
        XCTAssertEqual(result.countOfPendingTransactions, 2)
        XCTAssertEqual(result.current?.id, transactionID)
    }
    
    /// Call nextTransaction returning the next available.
    func testNextTransaction() async throws {
        // Given
        let verificationsUrl = URL(string: "\(urlBase)/v1.0/authenticators/verifications\(CloudAuthenticatorService.TransactionFilter.nextPending.rawValue)")!
        let transactionUrl = URL(string: "\(urlBase)/v1.0/authenticators/verifications")!
        
        MockURLProtocol.urls[verificationsUrl] = MockHTTPResponse(response: HTTPURLResponse(url: verificationsUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.transaction")
        
        // Where
        let service = CloudAuthenticatorService(with: "abc123", refreshUri: URL(string: "\(urlBase)/v1.0/")!, transactionUri: transactionUrl, authenticatorId: UUID().uuidString)
        
       let result = try await service.nextTransaction()
        
        // Then
        XCTAssertEqual(result.countOfPendingTransactions, 2)
        XCTAssertEqual(result.current?.id, "b1bd512f-094e-4792-a0f6-6b9c75f50466")
    }
    
    /// Call nextTransaction returning the next available and compare te sorten transacton identifier.
    func testNextTransactionShortenId() async throws {
        // Given
        let verificationsUrl = URL(string: "\(urlBase)/v1.0/authenticators/verifications\(CloudAuthenticatorService.TransactionFilter.nextPending.rawValue)")!
        let transactionUrl = URL(string: "\(urlBase)/v1.0/authenticators/verifications")!
        
        MockURLProtocol.urls[verificationsUrl] = MockHTTPResponse(response: HTTPURLResponse(url: verificationsUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.transaction")
        
        // Where
        let service = CloudAuthenticatorService(with: "abc123", refreshUri: URL(string: "\(urlBase)/v1.0/")!, transactionUri: transactionUrl, authenticatorId: UUID().uuidString)
        
       let result = try await service.nextTransaction()
        
        // Then
        XCTAssertEqual(result.countOfPendingTransactions, 2)
        XCTAssertEqual(result.current?.id, "b1bd512f-094e-4792-a0f6-6b9c75f50466")
        XCTAssertEqual(result.current?.shortId, "b1bd512f")
    }
    
    /// Call nextTransaction with no transactions.
    func testNoNextTransaction() async throws {
        // Given
        let verificationsUrl = URL(string: "\(urlBase)/v1.0/authenticators/verifications\(CloudAuthenticatorService.TransactionFilter.nextPending.rawValue)")!
        let transactionUrl = URL(string: "\(urlBase)/v1.0/authenticators/verifications")!
        
        MockURLProtocol.urls[verificationsUrl] = MockHTTPResponse(response: HTTPURLResponse(url: verificationsUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.notransaction")
        
        // Where
        let service = CloudAuthenticatorService(with: "abc123", refreshUri: URL(string: "\(urlBase)/v1.0/")!, transactionUri: transactionUrl, authenticatorId: UUID().uuidString)
        
        let result = try await service.nextTransaction()
        
        // Then
        XCTAssertEqual(result.countOfPendingTransactions, 0)
        XCTAssertNil(result.current)
    }
    
    /// Call completeTransaction, returns invalidSignedData error
    func testCompleteNoPendingTransaction() async throws {
        // Given
        let transactionUrl = URL(string: "\(urlBase)/v1.0/authenticators/verifications")!
        
        MockURLProtocol.urls[transactionUrl] = MockHTTPResponse(response: HTTPURLResponse(url: transactionUrl, statusCode: 204, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.transaction")
        
        // Where
        let service = CloudAuthenticatorService(with: "abc123", refreshUri: URL(string: "\(urlBase)/v1.0/")!, transactionUri: transactionUrl, authenticatorId: UUID().uuidString)
        
        // Then
        do {
            try await service.completeTransaction(signedData: "abcdef")
        }
        catch let error {
            XCTAssertEqual(error as? MFAServiceError, .invalidPendingTransaction)
        }
    }
    
    /// Call completeTransaction, returns invalidSignedData error
    func testCompleteTransactionInvalidSigning() async throws {
        // Given
        let verificationsUrl = URL(string: "\(urlBase)/v1.0/authenticators/verifications\(CloudAuthenticatorService.TransactionFilter.nextPending.rawValue)")!
        let transactionUrl = URL(string: "\(urlBase)/v1.0/authenticators/verifications")!
        
        MockURLProtocol.urls[verificationsUrl] = MockHTTPResponse(response: HTTPURLResponse(url: verificationsUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.transaction")
        MockURLProtocol.urls[transactionUrl] = MockHTTPResponse(response: HTTPURLResponse(url: transactionUrl, statusCode: 400, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.transaction")
        
        
        // Where
        let service = CloudAuthenticatorService(with: "abc123", refreshUri: URL(string: "\(urlBase)/v1.0/")!, transactionUri: transactionUrl, authenticatorId: UUID().uuidString)
        
        let _ = try await service.nextTransaction()
        
        // Then
        do {
            try await service.completeTransaction(signedData: "abcdef")
        }
        catch let error {
            XCTAssertNotNil(error)
        }
    }
    
    /// Call completeTransaction with a deny.
    func testCompleteTransactionWithDeny() async throws {
        // Given
        let verificationsUrl = URL(string: "\(urlBase)/v1.0/authenticators/verifications\(CloudAuthenticatorService.TransactionFilter.nextPending.rawValue)")!
        let transactionUrl = URL(string: "\(urlBase)/v1.0/authenticators/verifications")!
        let postbackUrl = URL(string: "\(urlBase)/v1.0/authenticators/verifications/b1bd512f-094e-4792-a0f6-6b9c75f50466")!
        
        MockURLProtocol.urls[verificationsUrl] = MockHTTPResponse(response: HTTPURLResponse(url: verificationsUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.transaction")
        MockURLProtocol.urls[postbackUrl] = MockHTTPResponse(response: HTTPURLResponse(url: postbackUrl, statusCode: 204, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.transaction")
        
        // Where
        let service = CloudAuthenticatorService(with: "abc123", refreshUri: URL(string: "\(urlBase)/v1.0/")!, transactionUri: transactionUrl, authenticatorId: UUID().uuidString)
        
        let _ = try await service.nextTransaction()
        
        // Then
        try await service.completeTransaction(action: .deny, signedData: "xyz")
        XCTAssert(true, "Transaction completed")
    }
    
    /// Call completeTransaction with a deny with fraud.
    func testCompleteTransactionMarkAsFraud() async throws {
        // Given
        let verificationsUrl = URL(string: "\(urlBase)/v1.0/authenticators/verifications\(CloudAuthenticatorService.TransactionFilter.nextPending.rawValue)")!
        let transactionUrl = URL(string: "\(urlBase)/v1.0/authenticators/verifications")!
        let postbackUrl = URL(string: "\(urlBase)/v1.0/authenticators/verifications/b1bd512f-094e-4792-a0f6-6b9c75f50466")!
        
        MockURLProtocol.urls[verificationsUrl] = MockHTTPResponse(response: HTTPURLResponse(url: verificationsUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.transaction")
        MockURLProtocol.urls[postbackUrl] = MockHTTPResponse(response: HTTPURLResponse(url: postbackUrl, statusCode: 204, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.transaction")
        
        // Where
        let service = CloudAuthenticatorService(with: "abc123", refreshUri: URL(string: "\(urlBase)/v1.0/")!, transactionUri: transactionUrl, authenticatorId: UUID().uuidString)
        
        let _ = try await service.nextTransaction()
        
        // Then
        try await service.completeTransaction(action: .markAsFraud, signedData: "xyz")
        XCTAssert(true, "Transaction completed")
    }
    
    /// Call completeTransaction with a deny biometry failed.
    func testCompleteTransactionFailedBiometry() async throws {
        // Given
        let verificationsUrl = URL(string: "\(urlBase)/v1.0/authenticators/verifications\(CloudAuthenticatorService.TransactionFilter.nextPending.rawValue)")!
        let transactionUrl = URL(string: "\(urlBase)/v1.0/authenticators/verifications")!
        let postbackUrl = URL(string: "\(urlBase)/v1.0/authenticators/verifications/b1bd512f-094e-4792-a0f6-6b9c75f50466")!
        
        MockURLProtocol.urls[verificationsUrl] = MockHTTPResponse(response: HTTPURLResponse(url: verificationsUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.transaction")
        MockURLProtocol.urls[postbackUrl] = MockHTTPResponse(response: HTTPURLResponse(url: postbackUrl, statusCode: 204, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.transaction")
        
        // Where
        let service = CloudAuthenticatorService(with: "abc123", refreshUri: URL(string: "\(urlBase)/v1.0/")!, transactionUri: transactionUrl, authenticatorId: UUID().uuidString)
        
        let _ = try await service.nextTransaction()
        
        // Then
        try await service.completeTransaction(action: .failedBiometry, signedData: "xyz")
        XCTAssert(true, "Transaction completed")
    }
    
    /// Call completeTransaction, returns invalidSignedData error
    func testCompleteTransactionSuccess() async throws {
        // Given
        let verificationsUrl = URL(string: "\(urlBase)/v1.0/authenticators/verifications\(CloudAuthenticatorService.TransactionFilter.nextPending.rawValue)")!
        let transactionUrl = URL(string: "\(urlBase)/v1.0/authenticators/verifications")!
        let postbackUrl = URL(string: "\(urlBase)/v1.0/authenticators/verifications/b1bd512f-094e-4792-a0f6-6b9c75f50466")!
        
        MockURLProtocol.urls[verificationsUrl] = MockHTTPResponse(response: HTTPURLResponse(url: verificationsUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.transaction")
        MockURLProtocol.urls[postbackUrl] = MockHTTPResponse(response: HTTPURLResponse(url: postbackUrl, statusCode: 204, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.transaction")
        
        // Where
        let service = CloudAuthenticatorService(with: "abc123", refreshUri: URL(string: "\(urlBase)/v1.0/")!, transactionUri: transactionUrl, authenticatorId: UUID().uuidString)
        
        let _ = try await service.nextTransaction()
        
        // Then
        try await service.completeTransaction(signedData: "xyz")
        XCTAssert(true, "Transaction completed")
    }
    
    /// Call completeTransaction, check the currentPendingTransaction is nil
    func testCheckForNilPendingTransaction() async throws {
        // Given
        let verificationsUrl = URL(string: "\(urlBase)/v1.0/authenticators/verifications\(CloudAuthenticatorService.TransactionFilter.nextPending.rawValue)")!
        let transactionUrl = URL(string: "\(urlBase)/v1.0/authenticators/verifications")!
        let postbackUrl = URL(string: "\(urlBase)/v1.0/authenticators/verifications/b1bd512f-094e-4792-a0f6-6b9c75f50466")!
        
        MockURLProtocol.urls[verificationsUrl] = MockHTTPResponse(response: HTTPURLResponse(url: verificationsUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.transaction")
        MockURLProtocol.urls[postbackUrl] = MockHTTPResponse(response: HTTPURLResponse(url: postbackUrl, statusCode: 204, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.transaction")
        
        // Where
        let service = CloudAuthenticatorService(with: "abc123", refreshUri: URL(string: "\(urlBase)/v1.0/")!, transactionUri: transactionUrl, authenticatorId: UUID().uuidString)
        
        // Then
        var pendingTransaction = await service.currentPendingTransaction
        XCTAssertNil(pendingTransaction)
        
        // Then
        let _ = try await service.nextTransaction()
        pendingTransaction = await service.currentPendingTransaction
        XCTAssertNotNil(pendingTransaction)
        
        // Then
        try await service.completeTransaction(signedData: "xyz")
        XCTAssert(true, "Transaction completed")
        
        // Then
        pendingTransaction = await service.currentPendingTransaction
        XCTAssertNil(pendingTransaction)
    }
    
    /// Call login
    func testPerformLoginSuccess() async throws {
        // Given
        let loginUrl = URL(string: "\(urlBase)/v2.0/factors/qr")!
        
        MockURLProtocol.urls[loginUrl] = MockHTTPResponse(response: HTTPURLResponse(url: loginUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.login")
        
        // Where
        let service = CloudAuthenticatorService(with: "abc123", refreshUri: URL(string: "\(urlBase)/v1.0/")!, transactionUri:  URL(string: "\(urlBase)/v1.0/")!, authenticatorId: UUID().uuidString)
        
        // Then
        try await service.login(using: loginUrl, code: "abc123")
        XCTAssert(true, "Transaction completed")
    }
    
    /// Call login
    func testPerformLoginFailed() async throws {
        // Given
        let loginUrl = URL(string: "\(urlBase)/v2.0/factors/qr")!
        
        MockURLProtocol.urls[loginUrl] = MockHTTPResponse(response: HTTPURLResponse(url: loginUrl, statusCode: 404, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.failedlogin")
        
        // Where
        let service = CloudAuthenticatorService(with: "abc123", refreshUri: URL(string: "\(urlBase)/v1.0/")!, transactionUri:  URL(string: "\(urlBase)/v1.0/")!, authenticatorId: UUID().uuidString)
        
        // Then
        do {
            try await service.login(using: loginUrl, code: "abc123")
            XCTAssert(true, "Transaction completed")
        }
        catch let error {
            XCTAssertNotNil(error, error.localizedDescription)
        }
    }
}
