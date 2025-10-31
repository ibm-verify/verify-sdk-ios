//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import XCTest
import Authentication
import Core
import CryptoKit
@testable import MFA

class OnPremiseAuthenticatorServiceTest: XCTestCase {

    let urlBase = "https://mmfa.securitypoc.com"
    
    override func setUp() {
        super.setUp()
        URLProtocol.registerClass(MockURLProtocol.self)
    }

    override func tearDown() {
        super.tearDown()
        URLProtocol.unregisterClass(MockURLProtocol.self)
    }

    // MARK: - Refresh
    
    /// Attempts to refresh the access token for an authenticator
    func testRefreshToken() async throws {
        let tokenUrl = URL(string: "\(urlBase)/mga/sps/oauth/oauth20/token")!
        MockURLProtocol.urls[tokenUrl] = MockHTTPResponse(response: HTTPURLResponse(url: tokenUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.tokenRefresh")
        
        // Where
        let service = OnPremiseAuthenticatorService(with: "wxt272", refreshUri: URL(string: "\(urlBase)/mga/sps/oauth/oauth20/token")!, transactionUri: URL(string: "\(urlBase)/scim/Me")!, clientId: "abc123", authenticatorId: UUID().uuidString)
        let token = try? await service.refreshToken(using: "def456", accountName: "testuser", pushToken: "12356ndd")
        let accessToken = await service.accessToken
        
        // Then
        XCTAssertNotNil(token, "TokenInfo returned success.")
        XCTAssertEqual(token?.refreshToken, "Z9x8Y7")
        XCTAssertEqual("A1b2C3D4", accessToken)
        XCTAssertEqual(token?.accessToken, "A1b2C3D4")
        XCTAssertEqual(token?.additionalData["display_name"] as! String, "testuser")
    }
    
    /// Attempts to refresh the access token for an authenticator with an invalid pinned certificate.
    func testCertificateTrustFailedWithRefresh() async throws {
        // Given
        let tokenUrl = URL(string: "\(urlBase)/mga/sps/oauth/oauth20/token")!
        MockURLProtocol.urls[tokenUrl] = MockHTTPResponse(response: HTTPURLResponse(url: tokenUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.tokenRefresh")
        
        let publicKeyCertificate = "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"
        
        let pinnedCertificate = PinnedCertificateDelegate(with: publicKeyCertificate)
        
        // Where
        let service = OnPremiseAuthenticatorService(with: "wxt272", refreshUri: URL(string: "\(urlBase)/mga/sps/oauth/oauth20/token")!, transactionUri: URL(string: "\(urlBase)/scim/Me")!, clientId: "abc123", authenticatorId: UUID().uuidString, certificateTrust: pinnedCertificate)
        
        // Then
        do {
            let _ = try await service.refreshToken(using: "def456")
        }
        catch let error {
            XCTAssert(error is URLError)
        }
    }
    
    /// Attempts to refresh the access token for an authenticator using self signed certificate
    func testSelfSignedCertificateTrustWithRefresh() async throws {
        // Given
        let tokenUrl = URL(string: "\(urlBase)/mga/sps/oauth/oauth20/token")!
        MockURLProtocol.urls[tokenUrl] = MockHTTPResponse(response: HTTPURLResponse(url: tokenUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.tokenRefresh")
        
        // Where
        let service = OnPremiseAuthenticatorService(with: "wxt272", refreshUri: URL(string: "\(urlBase)/mga/sps/oauth/oauth20/token")!, transactionUri: URL(string: "\(urlBase)/scim/Me")!, clientId: "abc123", authenticatorId: UUID().uuidString, certificateTrust: SelfSignedCertificateDelegate())
        
        // Then
        do {
            let _ = try await service.refreshToken(using: "def456")
        }
        catch let error {
            XCTAssert(error is URLSessionError)
        }
    }

    
    /// Attempts to refresh the access token for an authenticator with no push token, but with additional data.
    func testRefreshTokenNoPushWithAdditionalData() async throws {
        let tokenUrl = URL(string: "\(urlBase)/mga/sps/oauth/oauth20/token")!
        MockURLProtocol.urls[tokenUrl] = MockHTTPResponse(response: HTTPURLResponse(url: tokenUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.tokenRefresh")
        
        // Where
        let service = OnPremiseAuthenticatorService(with: "wxt272", refreshUri: URL(string: "\(urlBase)/mga/sps/oauth/oauth20/token")!, transactionUri: URL(string: "\(urlBase)/scim/Me")!, clientId: "abc123", authenticatorId: UUID().uuidString)
        let token = try? await service.refreshToken(using: "def456", accountName: "testuser", additionalData: ["country": "Australia"])
        
        
        // Then
        XCTAssertNotNil(token, "TokenInfo returned success.")
        XCTAssertEqual(token?.refreshToken, "Z9x8Y7")
        XCTAssertEqual(token?.accessToken, "A1b2C3D4")
        XCTAssertEqual(token?.additionalData["display_name"] as! String, "testuser")
    }
    
    /// Attempts to refresh the access token but throwns an error.
    func testRefreshTokenThrowError() async throws {
        let tokenUrl = URL(string: "\(urlBase)/mga/sps/oauth/oauth20/token")!
        MockURLProtocol.urls[tokenUrl] = MockHTTPResponse(response: HTTPURLResponse(url: tokenUrl, statusCode: 400, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.tokenRefresh")
        
        // Where
        let service = OnPremiseAuthenticatorService(with: "wxt272", refreshUri: URL(string: "\(urlBase)/mga/sps/oauth/oauth20/token")!, transactionUri: URL(string: "\(urlBase)/scim/Me")!, clientId: "abc123", authenticatorId: UUID().uuidString)
        
        do {
            let _ = try await service.refreshToken(using: "def456", accountName: "testuser", additionalData: ["country": "Australia"])
        }
        catch let error {
            XCTAssertTrue(error is URLSessionError)
        }
    }
    
    // MARK: - Pending trasactions
    
    /// Call nextTransaction returning the next available.
    func testNextTransaction() async throws {
        // Given
        let transactionID = "fcd138c0-396f-4298-8c14-27a5196ad05e"
        let transactionUrl = URL(string: "\(urlBase)/scim/Me?attributes=urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Transaction:transactionsPending,urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Transaction:attributesPending")!
        let challenageUrl = URL(string: "\(urlBase)/mga/sps/apiauthsvc?MmfaTransactionId=FCD138C0-396F-4298-8C14-27A5196AD05E")!
        
        MockURLProtocol.urls[transactionUrl] = MockHTTPResponse(response: HTTPURLResponse(url: transactionUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.transaction")
        MockURLProtocol.urls[challenageUrl] = MockHTTPResponse(response: HTTPURLResponse(url: challenageUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.transactionChallenge")
        
        // Where
        let authenticator = try await OnPremiseRegistrationProviderTest().testFinalizeRegistration() as! OnPremiseAuthenticator
        let service = OnPremiseAuthenticatorService(with: authenticator.token.accessToken, refreshUri: authenticator.refreshUri, transactionUri: authenticator.transactionUri, clientId: authenticator.clientId, authenticatorId: "296C632A-E142-413E-9CDE-B547A1258BA8")
        
        // Then
        let result = try await service.nextTransaction()
        XCTAssertEqual(result.countOfPendingTransactions, 2)
        XCTAssertEqual(result.current?.id, transactionID)
    }
    
    /// Test an on-premise transaction with the SDK performing the signing.
    func testNextTransactionWithKeys() async throws {
        // Given
        let transactionID = "fcd138c0-396f-4298-8c14-27a5196ad05e"
        let transactionUrl = URL(string: "\(urlBase)/scim/Me?attributes=urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Transaction:transactionsPending,urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Transaction:attributesPending")!
        let challenageUrl = URL(string: "\(urlBase)/mga/sps/apiauthsvc?MmfaTransactionId=FCD138C0-396F-4298-8C14-27A5196AD05E")!
        let completeTransactionUrl = URL(string: "\(urlBase)/mga/sps/apiauthsvc?StateId=3oU0Y2A52YnkX39Dnz3dAxRi49ynz7lDMgO3BUHuY57syFoUJ92VLCXQtGXFvuKX29S8gEqhKshSJ5TU2UGKunsXi4SJ9VR0ET3An6JTpPkE14NjMqreYhzTUnglrqVW")!
        
        MockURLProtocol.urls[transactionUrl] = MockHTTPResponse(response: HTTPURLResponse(url: transactionUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.transaction")
        MockURLProtocol.urls[challenageUrl] = MockHTTPResponse(response: HTTPURLResponse(url: challenageUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.transactionChallenge")
        MockURLProtocol.urls[completeTransactionUrl] = MockHTTPResponse(response: HTTPURLResponse(url: completeTransactionUrl, statusCode: 204, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.transactionVerify")
        
        // Where
        let authenticator = try await OnPremiseRegistrationProviderTest().testFinalizeRegistrationWithKeys() as! OnPremiseAuthenticator
        let service = OnPremiseAuthenticatorService(with: authenticator.token.accessToken, refreshUri: authenticator.refreshUri, transactionUri: authenticator.transactionUri, clientId: authenticator.clientId, authenticatorId: "296C632A-E142-413E-9CDE-B547A1258BA8")
        
        // Then
        let result = try await service.nextTransaction()
        XCTAssertEqual(result.countOfPendingTransactions, 2)
        XCTAssertEqual(result.current?.id, transactionID)
        
        // Then
        do {
            if let factorType = authenticator.allowedFactors.first {
                try await service.completeTransaction(factor: factorType)
            }
        }
        catch let error {
            XCTAssertTrue(error is MFAServiceError)
        }
    }
    
    
    func testNextTransactionInvalidData() async throws {
        // Given
        let transactionUrl = URL(string: "\(urlBase)/scim/Me?attributes=urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Transaction:transactionsPending,urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Transaction:attributesPending")!
        
        MockURLProtocol.urls[transactionUrl] = MockHTTPResponse(response: HTTPURLResponse(url: transactionUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.transactionInvalid")
        
        // Where
        let authenticator = try await OnPremiseRegistrationProviderTest().testFinalizeRegistration() as! OnPremiseAuthenticator
        let service = OnPremiseAuthenticatorService(with: authenticator.token.accessToken, refreshUri: authenticator.refreshUri, transactionUri: authenticator.transactionUri, clientId: authenticator.clientId, authenticatorId: "296C632A-E142-413E-9CDE-B547A1258BA8")
        
        // Then
        do {
            let _ = try await service.nextTransaction()
        }
        catch let error {
            XCTAssertTrue(error is MFAServiceError)
        }
    }
    
    /// Call nextTransaction by a transaction identifier.
    func testNextTransactionWithID() async throws {
        // Given
        let transactionID = "dea8b846-76dc-4786-9941-daf9fa86427e"
        let transactionUrl = URL(string: "\(urlBase)/scim/Me?attributes=urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Transaction:transactionsPending,urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Transaction:attributesPending")!
        let challenageUrl = URL(string: "\(urlBase)/mga/sps/apiauthsvc?MmfaTransactionId=DEA8B846-76DC-4786-9941-DAF9FA86427E")!
        
        MockURLProtocol.urls[transactionUrl] = MockHTTPResponse(response: HTTPURLResponse(url: transactionUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.transaction")
        MockURLProtocol.urls[challenageUrl] = MockHTTPResponse(response: HTTPURLResponse(url: challenageUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.transactionChallenge")
        
        // Where
        let authenticator = try await OnPremiseRegistrationProviderTest().testFinalizeRegistration() as! OnPremiseAuthenticator
        let service = OnPremiseAuthenticatorService(with: authenticator.token.accessToken, refreshUri: authenticator.refreshUri, transactionUri: authenticator.transactionUri, clientId: authenticator.clientId, authenticatorId: "296C632A-E142-413E-9CDE-B547A1258BA8")
        
        // Then
        let result = try await service.nextTransaction(with: transactionID)
        XCTAssertEqual(result.countOfPendingTransactions, 2)
        XCTAssertEqual(result.current?.id, transactionID)
    }
    
    /// Call nextTransaction returning the next available where no authenticator identifier is found.
    func testNextTransactionNoAuthenticator() async throws {
        // Given
        let transactionID = "dea8b846-76dc-4786-9941-daf9fa86427e"
        let transactionUrl = URL(string: "\(urlBase)/scim/Me?attributes=urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Transaction:transactionsPending,urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Transaction:attributesPending")!
        let challenageUrl = URL(string: "\(urlBase)/mga/sps/apiauthsvc?MmfaTransactionId=DEA8B846-76DC-4786-9941-DAF9FA86427E")!
           
        MockURLProtocol.urls[transactionUrl] = MockHTTPResponse(response: HTTPURLResponse(url: transactionUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.transactionNoAuthenticator")
        MockURLProtocol.urls[challenageUrl] = MockHTTPResponse(response: HTTPURLResponse(url: challenageUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.transactionChallenge")
        
        // Where
        let authenticator = try await OnPremiseRegistrationProviderTest().testFinalizeRegistration() as! OnPremiseAuthenticator
        let service = OnPremiseAuthenticatorService(with: authenticator.token.accessToken, refreshUri: authenticator.refreshUri, transactionUri: authenticator.transactionUri, clientId: authenticator.clientId, authenticatorId: "296C632A-E142-413E-9CDE-B547A1258BA8")
        
        // Then
        let result = try await service.nextTransaction()
        XCTAssertEqual(result.countOfPendingTransactions, 1)
        XCTAssertEqual(result.current?.id, transactionID)
    }
    
    
    
    /// Call nextTransaction when no transactions are pending
    func testNoNextTransaction() async throws {
        // Given
        let transactionUrl = URL(string: "\(urlBase)/scim/Me?attributes=urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Transaction:transactionsPending,urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Transaction:attributesPending")!
         
        MockURLProtocol.urls[transactionUrl] = MockHTTPResponse(response: HTTPURLResponse(url: transactionUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.notransaction")

        // Where
        let authenticator = try await OnPremiseRegistrationProviderTest().testFinalizeRegistration() as! OnPremiseAuthenticator
        
        // Where
        let service = OnPremiseAuthenticatorService(with: authenticator.token.accessToken, refreshUri: authenticator.refreshUri, transactionUri: authenticator.transactionUri, clientId: authenticator.clientId, authenticatorId: authenticator.id)
        
        let result = try await service.nextTransaction()
        
        // Then
        XCTAssertEqual(result.countOfPendingTransactions, 0)
        XCTAssertNil(result.current)
    }
    
    /// Call nextTransaction and uses the default message from the bundle resource.
    func testNextTransactionDefaultMessage() async throws {
        // Given
        let transactionUrl = URL(string: "\(urlBase)/scim/Me?attributes=urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Transaction:transactionsPending,urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Transaction:attributesPending")!
        let challenageUrl = URL(string: "\(urlBase)/mga/sps/apiauthsvc?MmfaTransactionId=FCD138C0-396F-4298-8C14-27A5196AD05E")!
        
        MockURLProtocol.urls[transactionUrl] = MockHTTPResponse(response: HTTPURLResponse(url: transactionUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.transactionDefaultMessage")
        MockURLProtocol.urls[challenageUrl] = MockHTTPResponse(response: HTTPURLResponse(url: challenageUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.transactionChallenge")
        
        // Where
        let authenticator = try await OnPremiseRegistrationProviderTest().testFinalizeRegistration() as! OnPremiseAuthenticator
        let service = OnPremiseAuthenticatorService(with: authenticator.token.accessToken, refreshUri: authenticator.refreshUri, transactionUri: authenticator.transactionUri, clientId: authenticator.clientId, authenticatorId: "296C632A-E142-413E-9CDE-B547A1258BA8")
        
        // Then
        let result = try await service.nextTransaction()
        XCTAssertEqual(result.current?.message, "You have a pending request")
    }
    
    /// Call nextTransaction where the challenge is not present.  Occurs on older versions of ISMA aka < v9.0.6
    func testNextTransactionInvalidSigningChallenge() async throws {
        // Given
        let transactionUrl = URL(string: "\(urlBase)/scim/Me?attributes=urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Transaction:transactionsPending,urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Transaction:attributesPending")!
        let challenageUrl = URL(string: "\(urlBase)/mga/sps/apiauthsvc?MmfaTransactionId=FCD138C0-396F-4298-8C14-27A5196AD05E")!
        
        MockURLProtocol.urls[transactionUrl] = MockHTTPResponse(response: HTTPURLResponse(url: transactionUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.transaction")
        MockURLProtocol.urls[challenageUrl] = MockHTTPResponse(response: HTTPURLResponse(url: challenageUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.transactionChallengeOldISAM")
        
        // Where
        let authenticator = try await OnPremiseRegistrationProviderTest().testFinalizeRegistration() as! OnPremiseAuthenticator
        let service = OnPremiseAuthenticatorService(with: authenticator.token.accessToken, refreshUri: authenticator.refreshUri, transactionUri: authenticator.transactionUri, clientId: authenticator.clientId, authenticatorId: "296C632A-E142-413E-9CDE-B547A1258BA8")
        
        // Then
        do {
            let _ = try await service.nextTransaction()
        }
        catch let error {
            XCTAssertTrue(error is MFAServiceError)
        }
    }
    
    /// Call nextTransaction where the keyHandle to identify the factor can't be parsed.
    func testNextTransactionInvalidChallengeKeyHandle() async throws {
        // Given
        let transactionUrl = URL(string: "\(urlBase)/scim/Me?attributes=urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Transaction:transactionsPending,urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Transaction:attributesPending")!
        let challenageUrl = URL(string: "\(urlBase)/mga/sps/apiauthsvc?MmfaTransactionId=FCD138C0-396F-4298-8C14-27A5196AD05E")!
        
        MockURLProtocol.urls[transactionUrl] = MockHTTPResponse(response: HTTPURLResponse(url: transactionUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.transaction")
        MockURLProtocol.urls[challenageUrl] = MockHTTPResponse(response: HTTPURLResponse(url: challenageUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.transactionChallengeInvalidKeyHandle")
        
        // Where
        let authenticator = try await OnPremiseRegistrationProviderTest().testFinalizeRegistration() as! OnPremiseAuthenticator
        let service = OnPremiseAuthenticatorService(with: authenticator.token.accessToken, refreshUri: authenticator.refreshUri, transactionUri: authenticator.transactionUri, clientId: authenticator.clientId, authenticatorId: "296C632A-E142-413E-9CDE-B547A1258BA8")
        
        // Then
        do {
            let _ = try await service.nextTransaction()
        }
        catch let error {
            XCTAssertTrue(error is MFAServiceError)
        }
    }
    
    /// Call nextTransaction where attributes contain additional data to be appended to the PedndingTransactionInfo.
    func testNextTransactionAdditionalData() async throws {
        // Given
        let transactionUrl = URL(string: "\(urlBase)/scim/Me?attributes=urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Transaction:transactionsPending,urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Transaction:attributesPending")!
        let challenageUrl = URL(string: "\(urlBase)/mga/sps/apiauthsvc?MmfaTransactionId=FCD138C0-396F-4298-8C14-27A5196AD05E")!
        
        MockURLProtocol.urls[transactionUrl] = MockHTTPResponse(response: HTTPURLResponse(url: transactionUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.transactionAdditionalData")
        MockURLProtocol.urls[challenageUrl] = MockHTTPResponse(response: HTTPURLResponse(url: challenageUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.transactionChallenge")
        
        // Where
        let authenticator = try await OnPremiseRegistrationProviderTest().testFinalizeRegistration() as! OnPremiseAuthenticator
        let service = OnPremiseAuthenticatorService(with: authenticator.token.accessToken, refreshUri: authenticator.refreshUri, transactionUri: authenticator.transactionUri, clientId: authenticator.clientId, authenticatorId: "296C632A-E142-413E-9CDE-B547A1258BA8")
        
        // Then
        let result = try await service.nextTransaction()
        XCTAssertEqual(result.countOfPendingTransactions, 2)
        XCTAssertEqual(result.current?.additionalData[.type], "transaction")
        XCTAssertEqual(result.current?.additionalData[.ipAddress], "8.8.8.8")
        XCTAssertEqual(result.current?.additionalData[.userAgent], "Browser")
        XCTAssertEqual(result.current?.additionalData[.location], "Gold Coast, Australia")
        XCTAssertEqual(result.current?.additionalData[.image], "https://picsum.photos/200/300")
        
        if let json = result.current?.additionalData[.custom] {
            if let dictionary = try? JSONSerialization.jsonObject(with: json.data(using: .utf8)!, options: []) as? [[String: Any]] {
                XCTAssertEqual(dictionary[0]["name"] as? String, "city")
                XCTAssertEqual(dictionary[0]["value"] as? String, "Surfers Paradise")
            }
        }
    }
    
    /// Call nextTransaction returning the service.
    func serviceWithNextTransaction() async throws -> MFAServiceDescriptor {
        // Given
        let transactionUrl = URL(string: "\(urlBase)/scim/Me?attributes=urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Transaction:transactionsPending,urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Transaction:attributesPending")!
        let challenageUrl = URL(string: "\(urlBase)/mga/sps/apiauthsvc?MmfaTransactionId=FCD138C0-396F-4298-8C14-27A5196AD05E")!
        
        MockURLProtocol.urls[transactionUrl] = MockHTTPResponse(response: HTTPURLResponse(url: transactionUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.transaction")
        MockURLProtocol.urls[challenageUrl] = MockHTTPResponse(response: HTTPURLResponse(url: challenageUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.transactionChallenge")
        
        // Where
        let authenticator = try await OnPremiseRegistrationProviderTest().testFinalizeRegistrationWithKeys() as! OnPremiseAuthenticator
        let service = OnPremiseAuthenticatorService(with: authenticator.token.accessToken, refreshUri: authenticator.refreshUri, transactionUri: authenticator.transactionUri, clientId: authenticator.clientId, authenticatorId: "296C632A-E142-413E-9CDE-B547A1258BA8")
        
        // Then
        let _ = try await service.nextTransaction()
        return service
    }
    
   
    // MARK: - Complete transactions
    
    /// Call completeTransaction, returns void, meaning success
    func testCompleteVerifyTransaction() async throws {
        // Given
        let postbackUrl = URL(string: "\(urlBase)/mga/sps/apiauthsvc?StateId=3oU0Y2A52YnkX39Dnz3dAxRi49ynz7lDMgO3BUHuY57syFoUJ92VLCXQtGXFvuKX29S8gEqhKshSJ5TU2UGKunsXi4SJ9VR0ET3An6JTpPkE14NjMqreYhzTUnglrqVW")!
        
        MockURLProtocol.urls[postbackUrl] = MockHTTPResponse(response: HTTPURLResponse(url: postbackUrl, statusCode: 204, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.transactionVerify")
        
        // Where
        let service = try await serviceWithNextTransaction()
        
        // Then
        try await service.completeTransaction(action: .verify, signedData: "xyz")
        XCTAssert(true, "Transaction completed")
    }
    
    /// Call completeTransaction, check the currentPendingTransaction is nil
    func testCheckForNilPendingTransaction() async throws {
        // Given
        let postbackUrl = URL(string: "\(urlBase)/mga/sps/apiauthsvc?StateId=3oU0Y2A52YnkX39Dnz3dAxRi49ynz7lDMgO3BUHuY57syFoUJ92VLCXQtGXFvuKX29S8gEqhKshSJ5TU2UGKunsXi4SJ9VR0ET3An6JTpPkE14NjMqreYhzTUnglrqVW")!
        
        MockURLProtocol.urls[postbackUrl] = MockHTTPResponse(response: HTTPURLResponse(url: postbackUrl, statusCode: 204, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.transactionVerify")
        
        // Where
        let service = try await serviceWithNextTransaction()
        
        // Then
        var pendingTransaction = await service.currentPendingTransaction
        XCTAssertNotNil(pendingTransaction)
        
        // Then
        try await service.completeTransaction(action: .verify, signedData: "xyz")
        XCTAssert(true, "Transaction completed")
        
        // Then
        pendingTransaction = await service.currentPendingTransaction
        XCTAssertNil(pendingTransaction)
    }
    
    /// Call completeTransaction, returns void meaning success
    func testCompleteDenyTransaction() async throws {
        // Given
        let postbackUrl = URL(string: "\(urlBase)/mga/sps/apiauthsvc?StateId=3oU0Y2A52YnkX39Dnz3dAxRi49ynz7lDMgO3BUHuY57syFoUJ92VLCXQtGXFvuKX29S8gEqhKshSJ5TU2UGKunsXi4SJ9VR0ET3An6JTpPkE14NjMqreYhzTUnglrqVW")!
        
        MockURLProtocol.urls[postbackUrl] = MockHTTPResponse(response: HTTPURLResponse(url: postbackUrl, statusCode: 204, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.transactionVerify")
        
        // Where
        let service = try await serviceWithNextTransaction()
        
        // Then
        try await service.completeTransaction(action: .deny, signedData: "xyz")
        XCTAssert(true, "Transaction completed")
    }
    
    /// Call completeTransaction, returns void meaning success
    func testCompleteVerifyTransactionAsError() async throws {
        // Given
        let postbackUrl = URL(string: "\(urlBase)/mga/sps/apiauthsvc?StateId=3oU0Y2A52YnkX39Dnz3dAxRi49ynz7lDMgO3BUHuY57syFoUJ92VLCXQtGXFvuKX29S8gEqhKshSJ5TU2UGKunsXi4SJ9VR0ET3An6JTpPkE14NjMqreYhzTUnglrqVW")!
        
        MockURLProtocol.urls[postbackUrl] = MockHTTPResponse(response: HTTPURLResponse(url: postbackUrl, statusCode: 400, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.transactionVerify")
        
        // Where
        let service = try await serviceWithNextTransaction()
        
        // Then
        do {
            try await service.completeTransaction(action: .verify, signedData: "abc123")
        }
        catch let error {
            XCTAssertTrue(error is URLSessionError)
        }
    }
    
    // MARK: - Login
    
    /// Call login
    func testPerformLoginFailed() async throws {
        // Given
        let loginUrl = URL(string: "\(urlBase)/mga/sps/apiauthsvc?PolicyId=urn:ibm:security:authentication:asf:qrcode_response")!
        
        MockURLProtocol.urls[loginUrl] = MockHTTPResponse(response: HTTPURLResponse(url: loginUrl, statusCode: 400, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.failedLogin")
        
        // Where
        let authenticator = try await OnPremiseRegistrationProviderTest().testFinalizeRegistrationWithKeys() as! OnPremiseAuthenticator
        let service = OnPremiseAuthenticatorService(with: authenticator.token.accessToken, refreshUri: authenticator.refreshUri, transactionUri: authenticator.transactionUri, clientId: authenticator.clientId, authenticatorId: "296C632A-E142-413E-9CDE-B547A1258BA8")
        
        // Then
        do {
            try await service.login(using: loginUrl, code: "abc123")
        }
        catch let error {
            XCTAssertNotNil(error, error.localizedDescription)
        }
    }
    
    /// Call login
    func testPerformLoginSuccess() async throws {
        // Given
        let loginUrl = URL(string: "\(urlBase)/mga/sps/apiauthsvc?PolicyId=urn:ibm:security:authentication:asf:qrcode_response")!
        
        MockURLProtocol.urls[loginUrl] = MockHTTPResponse(response: HTTPURLResponse(url: loginUrl, statusCode: 204, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.loginSuccess")
        
        // Where
        let authenticator = try await OnPremiseRegistrationProviderTest().testFinalizeRegistrationWithKeys() as! OnPremiseAuthenticator
        let service = OnPremiseAuthenticatorService(with: authenticator.token.accessToken, refreshUri: authenticator.refreshUri, transactionUri: authenticator.transactionUri, clientId: authenticator.clientId, authenticatorId: "296C632A-E142-413E-9CDE-B547A1258BA8")
        
        // Then
        do {
            try await service.login(using: authenticator.qrloginUri!, code: "abc123")
        }
        catch let error {
            XCTAssertNotNil(error, error.localizedDescription)
        }
    }
    
    /// Call login
    func testPerformQrLoginFailed() async throws {
        // Given
        let loginUrl = URL(string: "\(urlBase)/mga/sps/apiauthsvc?PolicyId=urn:ibm:security:authentication:asf:qrcode_response")!
        MockURLProtocol.urls[loginUrl] = MockHTTPResponse(response: HTTPURLResponse(url: loginUrl, statusCode: 401, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.failedQrLogin")
        
        // Where
        let url = Bundle.module.url(forResource: "onpremise.authenticator", withExtension: "json", subdirectory: "Files")!
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .formatted(.iso8061FormatterBehavior)
        
        let authenticator = try decoder.decode(OnPremiseAuthenticator.self, from: Data(contentsOf: url))
        let service = OnPremiseAuthenticatorService(with: authenticator.token.accessToken, refreshUri: authenticator.refreshUri, transactionUri: authenticator.transactionUri, clientId: authenticator.clientId, authenticatorId: authenticator.id)
        
        // Then
        do {
            try await service.login(using: authenticator.qrloginUri!, code: "VGZT-XFRB")
        }
        catch let error {
            XCTAssertNotNil(error, error.localizedDescription)
        }
    }
    
    
    // MARK: - Remove
    
    /// Call remove with success.
    func testRemoveAuthenticatorSuccess() async throws {
        // Given
        let loginUrl = URL(string: "\(urlBase)/scim/Me?attributes=urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Authenticator:authenticators")!
        
        MockURLProtocol.urls[loginUrl] = MockHTTPResponse(response: HTTPURLResponse(url: loginUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.removeAuthenticator")
        
        // Where
        let authenticator = try await OnPremiseRegistrationProviderTest().testFinalizeRegistrationWithKeys() as! OnPremiseAuthenticator
        let service = OnPremiseAuthenticatorService(with: authenticator.token.accessToken, refreshUri: authenticator.refreshUri, transactionUri: authenticator.transactionUri, clientId: authenticator.clientId, authenticatorId: "296C632A-E142-413E-9CDE-B547A1258BA8")
        
        // Then
        try await service.remove()
        XCTAssert(true, "Authenticator removed.")
    }
    
    /// Call remove failed.
    func testRemoveAuthenticatorFailed() async throws {
        // Given
        let loginUrl = URL(string: "\(urlBase)/scim/Me?attributes=urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Authenticator:authenticators")!
        
        MockURLProtocol.urls[loginUrl] = MockHTTPResponse(response: HTTPURLResponse(url: loginUrl, statusCode: 400, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.removeAuthenticatorFailed")
        
        // Where
        let authenticator = try await OnPremiseRegistrationProviderTest().testFinalizeRegistrationWithKeys() as! OnPremiseAuthenticator
        let service = OnPremiseAuthenticatorService(with: authenticator.token.accessToken, refreshUri: authenticator.refreshUri, transactionUri: authenticator.transactionUri, clientId: authenticator.clientId, authenticatorId: "296C632A-E142-413E-9CDE-B547A1258BA8")
        
        // Then
        do {
            try await service.remove()
        }
        catch let error {
            XCTAssertNotNil(error, error.localizedDescription)
        }
    }
}
