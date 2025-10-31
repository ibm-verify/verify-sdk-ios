//
// Copyright contributors to the IBM Verify DC SDK for iOS project
//

import XCTest
@testable import Core
@testable import DC

final class WalletServiceTest: XCTestCase {
    let scanResultRegister = """
    {
        "serviceBaseUrl": "https://127.0.0.1:9720/diagency",
        "oauthBaseUrl": "https://127.0.0.1:8436/oauth2"
    }
    """
    
    let scanResultPreview = URL(string: "https://diagency:9720/diagency/a2a/v1/messages/3711d7cb-7e78-42a5-b5fe-393b39657079/invitation?id=56d35054-98a7-4dab-8d7f-26e3f03eb2af")!
    
    let tokenUrl = URL(string: "https://127.0.0.1:8436/oauth2/token")!
    let agentUrl = URL(string: "https://127.0.0.1:9720/diagency/v1.0/diagency/info")!
    let connectionsUrl = URL(string: "https://127.0.0.1:9720/diagency/v1.0/diagency/connections")!
    let invitationsUrl = URL(string: "https://127.0.0.1:9720/diagency/v1.0/diagency/invitations")!
    let credentialsUrl = URL(string: "https://127.0.0.1:9720/diagency/v1.0/diagency/credentials?filter=%7B%22state%22:%22stored%22%7D")!
    let credentialFilterUrl = URL(string: "https://127.0.0.1:9720/diagency/v1.0/diagency/credentials?filter=%7B%22state%22:%22inbound_offer%22%7D")!
    let credentialWithIdUrl = URL(string: "https://127.0.0.1:9720/diagency/v1.0/diagency/credentials/543cdfbe-4422-4c8c-8af0-8badb93e15a1")!
    let credentialPreviewUrl = URL(string: "https://127.0.0.1:9720/diagency/v1.0/diagency/invitation_processor")!
    let verificationFilterUrl = URL(string: "https://127.0.0.1:9720/diagency/v1.0/diagency/verifications?state=inbound_proof_request")!
    let verificationUrl = URL(string: "https://127.0.0.1:9720/diagency/v1.0/diagency/verifications/18f9a9f7-2066-4b8e-b55d-8c367f52bac2")!
    
    /// Flag to Ignore SSL cetificates.  **true** to resolve against a hosted endpoint otherwise **false** to use local files.
    let ignoreSSLCertificate = false
    
    override func setUpWithError() throws {
        try super.setUpWithError()
        URLProtocol.registerClass(MockURLProtocol.self)
        
        // Mock HTTP responses
        MockURLProtocol.urls[tokenUrl] = MockHTTPResponse(response: HTTPURLResponse(url: tokenUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "user.token")
        MockURLProtocol.urls[agentUrl] = MockHTTPResponse(response: HTTPURLResponse(url: agentUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "user.agent.info")
        MockURLProtocol.urls[connectionsUrl] = MockHTTPResponse(response: HTTPURLResponse(url: connectionsUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "user.conections")
        MockURLProtocol.urls[invitationsUrl] = MockHTTPResponse(response: HTTPURLResponse(url: invitationsUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "user.invitations")
        MockURLProtocol.urls[credentialsUrl] = MockHTTPResponse(response: HTTPURLResponse(url: credentialsUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "user.credentials-mixed")
        MockURLProtocol.urls[credentialFilterUrl] = MockHTTPResponse(response: HTTPURLResponse(url: credentialFilterUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "user.credentials")
        MockURLProtocol.urls[credentialWithIdUrl] = MockHTTPResponse(response: HTTPURLResponse(url: credentialWithIdUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "user.credential-indy")
        MockURLProtocol.urls[credentialPreviewUrl] = MockHTTPResponse(response: HTTPURLResponse(url: credentialPreviewUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "user.invitation-processor-cred-offer-mdoc")
        MockURLProtocol.urls[verificationFilterUrl] = MockHTTPResponse(response: HTTPURLResponse(url: verificationFilterUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "user.verification-proofs-mixed")
    }

    override func tearDownWithError() throws {
        try super.tearDownWithError()
        URLProtocol.unregisterClass(MockURLProtocol.self)
    }
    
    // MARK: Initiate Wallet Service
    func initiateWallet() async throws -> Wallet {
        let provider = WalletProvider(json: scanResultRegister, ignoreSSLCertificate: ignoreSSLCertificate)
        return try await provider.register(with: "John", clientId: "abc123", accessToken: "bcd234", refreshToken: "def345")
    }
    
    
    /// Tests the initiation of the `WalletService`.
    func testInitiate() async throws {
        // Given, Where
        let wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        
        // Then
        XCTAssertNotNil(service)
    }
    
    /// Tests the initiation of the `WalletService` with  a URLSession delegate.
    func testInitiateWithUrlDelegate() async throws {
        // Given, Where
        let wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: SelfSignedCertificateDelegate())
        
        // Then
        XCTAssertNotNil(service)
    }
    
    // MARK: Refresh token
    
    /// Tests the initiation of the `WalletService` and refresh token.
    func testRefreshTooken() async throws {
        // Given, Where
        let wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        let token = try await service.refreshToken(using: "abc123", accountName: "Jane", pushToken: "abc123")
        
        // Then
        XCTAssertNotNil(token)
    }
    
    // MARK: Invitations
    
    /// Tests the initiation of the `WalletService` and retrieve invitations.
    func testInitiateWithInvitations() async throws {
        // Given, Where
        var wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        let invitations = try await service.retrieveInvitations()
        wallet.invitations = invitations
        XCTAssertEqual(wallet.invitations.count, invitations.count)
    }
    
    /// Tests the initiation of the `WalletService` and retrieve invitations but failed no data.
    func testInitiateWithInvitationsFailed() async throws {
        // Given, Where
        let wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        do {
            MockURLProtocol.urls[invitationsUrl] = MockHTTPResponse(response: HTTPURLResponse(url: invitationsUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "no-data")
            
            let _ = try await service.retrieveInvitations()
        }
        catch let error {
            XCTAssertNotNil(error)
        }
    }
    
    /// Tests the initiation of the `WalletService` and retrieve invitations but invalid data.
    func testInitiateWithInvitationsInvalid() async throws {
        // Given, Where
        let wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        do {
            MockURLProtocol.urls[invitationsUrl] = MockHTTPResponse(response: HTTPURLResponse(url: invitationsUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "user.token")
            let _ = try await service.retrieveInvitations()
        }
        catch let error {
            XCTAssertNotNil(error)
        }
    }
    
    /// Tests the initiation of the `WalletService` and create a initation preview.
    func testInitiateWithInvitationPreview() async throws {
        // Given, Where
        let wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        let preview = try await service.previewInvitation(using: scanResultPreview)
        
        // Then
        XCTAssertNotNil(preview)
    }
    
    /// Tests the initiation of the `WalletService` and create a initation credential preview in mDoc format.
    func testInitiateWithInvitationCredentialMDocPreview() async throws {
        // Given, Where
        let wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        let preview = try await service.previewInvitation(using: scanResultPreview)
        
        // Then
        XCTAssertNotNil(preview)
    }
    
    // MARK: Credentials
    
    /// Tests the initiation of the `WalletService` and create a initation credential preview in JSON-LD format.
    func testInitiateWithInvitationCredentialJSONLDPreview() async throws {
        // Given
        MockURLProtocol.urls[credentialPreviewUrl] = MockHTTPResponse(response: HTTPURLResponse(url: credentialPreviewUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "user.invitation-processor-cred-offer-jsonld")
        
        // Where
        let wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        let preview = try await service.previewInvitation(using: scanResultPreview)
        
        // Then
        XCTAssertNotNil(preview)
        
        // Then
        XCTAssertNotNil(preview.jsonRepresentation)
    }
    
    /// Tests the initiation of the `WalletService` and create a initation preview no data.
    func testInitiateWithInvitationPreviewFailed() async throws {
        // Given, Where
        let wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        do {
            let _ = try await service.previewInvitation(using: URL(string: "https://invalid.url")!)
        }
        catch let error {
            XCTAssertNotNil(error)
        }
    }
    
    /// Tests the initiation of the `WalletService` preview the credential.
    func testInitiateWithCredentialPreview() async throws {
        // Given, Where
        let wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        let preview = try await service.previewInvitation(using: scanResultPreview)
        
        // Then
        XCTAssertNotNil(preview)
        XCTAssertTrue(preview is CredentialPreviewInfo)
        
        // Then
        try await service.processCredential(with: preview as! CredentialPreviewInfo)
    }
    
    /// Tests the initiation of the `WalletService` and retrieve credentials with the default "stored" filter.
    func testRetrieveCredentialsWithDefaultFilter() async throws {
        // Given, Where
        var wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        let credentials = try await service.retrieveCredentials()
        wallet.credentials = credentials
        XCTAssertTrue(wallet.credentials.count >= 0)
    }
    
    /// Tests the initiation of the `WalletService` and retrieve credential of "inbound_offer" state.
    func testRetrieveCredentiaslWithFilter() async throws {
        // Given, Where
        var wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        let credentials = try await service.retrieveCredentials(filter: .inboundOffer)
        
        // Simulate the filtering which would normally occur on the server.
        wallet.credentials = credentials.filter({
            $0.type.state == .inboundOffer
        })
        XCTAssertEqual(wallet.credentials.count, 2)
    }
    /// Tests the initiation of the `WalletService` and retrieve credentials with the default "stored" filter fails
    func testRetrieveCredentialsWithDefaultFilterFailed() async throws {
        // Given, Where
        let wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        do {
            MockURLProtocol.urls[credentialsUrl] = MockHTTPResponse(response: HTTPURLResponse(url: credentialsUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "no-data")
            let _ =  try await service.retrieveCredentials()
        }
        catch let error {
            XCTAssertNotNil(error)
        }
    }
    
    /// Tests the initiation of the `WalletService` and retrieve credentials with the default "stored" filter fails with invalid data.
    func testRetrieveCredentialsWithDefaultFilterInvalid() async throws {
        // Given, Where
        let wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        do {
            MockURLProtocol.urls[credentialsUrl] = MockHTTPResponse(response: HTTPURLResponse(url: credentialsUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "user.invitations-invalid")
            let _ =  try await service.retrieveCredentials()
        }
        catch let error {
            XCTAssertNotNil(error)
        }
    }
    
    /// Tests the initiation of the `WalletService` and retrieve credential using an identifier.
    func testRetrieveCredentialWithIdentifier() async throws {
        // Given
        let identifier = "543cdfbe-4422-4c8c-8af0-8badb93e15a1"
        
        // Where
        let wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        let credential = try await service.retrieveCredential(with: identifier)
        XCTAssertNotNil(credential)
    }
    
    /// Tests the initiation of the `WalletService` and attempts retrieve credential using an identifier.
    func testRetrieveCredentialWithIdentifierFailed() async throws {
        // Given
        MockURLProtocol.urls[credentialWithIdUrl] = MockHTTPResponse(response: HTTPURLResponse(url: credentialWithIdUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "no-data")
         let identifier = "543cdfbe-4422-4c8c-8af0-8badb93e15a1"
        
        // Where
        let wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        do {
            let _ = try await service.retrieveCredential(with: identifier)
        }
        catch let error {
            XCTAssertNotNil(error)
        }
    }
    
    /// Tests the initiation of the `WalletService` and attempts retrieve credential using an identifier.
    func testRetrieveCredentialWithIdentifierInvalid() async throws {
        // Given
        MockURLProtocol.urls[credentialWithIdUrl] = MockHTTPResponse(response: HTTPURLResponse(url: credentialWithIdUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "user.invitations-invalid")
        let identifier = "543cdfbe-4422-4c8c-8af0-8badb93e15a1"
        
        // Where
        let wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        do {
            let _ = try await service.retrieveCredential(with: identifier)
        }
        catch let error {
            XCTAssertNotNil(error)
        }
    }
    
    /// Tests the initiation of the `WalletService` preview the credential and accept.
    func testInitiateWithCredentialPreviewAccept() async throws {
        // Given
        MockURLProtocol.urls[credentialWithIdUrl] = MockHTTPResponse(response: HTTPURLResponse(url: credentialWithIdUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "user.credential-mdoc")
        
        // Where
        let wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        service.delegate = self
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        let preview = try await service.previewInvitation(using: scanResultPreview)
        
        // Then
        XCTAssertNotNil(preview)
        
        do {
            try await service.processCredential(with: preview as! CredentialPreviewInfo)
        }
        catch let error {
            XCTAssertNil(error)
        }
    }
    
    /// Tests the initiation of the `WalletService` preview the credential and accept but failed.
    func testInitiateWithCredentialPreviewAcceptFailed() async throws {
        // Given
        MockURLProtocol.urls[credentialPreviewUrl] = MockHTTPResponse(response: HTTPURLResponse(url: credentialPreviewUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "no-data")
        
        // Where
        let wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        do {
            let _ = try await service.previewInvitation(using: scanResultPreview)
        }
        catch let error {
            XCTAssertNotNil(error)
        }
    }
    
    /// Tests the initiation of the `WalletService` preview the credential and accept but invalid response.
    func testInitiateWithCredentialPreviewAcceptInvalid() async throws {
        // Given
        MockURLProtocol.urls[credentialPreviewUrl] = MockHTTPResponse(response: HTTPURLResponse(url: credentialPreviewUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "user.invitations-invalid")
       
        // Where
        let wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        do {
            let _ = try await service.previewInvitation(using: scanResultPreview)
        }
        catch let error {
            XCTAssertNotNil(error)
        }
    }
    
    /// Tests the initiation of the `WalletService` preview the credential and reject.
    func testInitiateWithCredentialPreviewRejected() async throws {
        // Given
        MockURLProtocol.urls[credentialWithIdUrl] = MockHTTPResponse(response: HTTPURLResponse(url: credentialWithIdUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "user.credential-mdoc")
       
        // Where
        let wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        let preview = try await service.previewInvitation(using: scanResultPreview)
        
        // Then
        XCTAssertNotNil(preview)
        
        do {
            try await service.processCredential(with: preview as! CredentialPreviewInfo, action: .rejected)
        }
        catch let error {
            XCTAssertNil(error)
        }
    }
    
    /// Tests the initiation of the `WalletService` process the credential but failed.
    func testInitiateWithCredentialProcessFailed() async throws {
        // Given
        MockURLProtocol.urls[credentialWithIdUrl] = MockHTTPResponse(response: HTTPURLResponse(url: credentialWithIdUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "no-data")
        
        // Where
        let wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        let preview = try await service.previewInvitation(using: scanResultPreview)
        
        // Then
        XCTAssertNotNil(preview)
        
        do {
            try await service.processCredential(with: preview as! CredentialPreviewInfo)
        }
        catch let error {
            XCTAssertNotNil(error)
        }
    }
    
    /// Tests the initiation of the `WalletService` process the credential but invalid response.
    func testInitiateWithCredentialProcessInvalid() async throws {
        // Given
        MockURLProtocol.urls[credentialWithIdUrl] = MockHTTPResponse(response: HTTPURLResponse(url: credentialWithIdUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "user.invitations-invalid")
        
        // Where
        let wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        let preview = try await service.previewInvitation(using: scanResultPreview)
        
        // Then
        XCTAssertNotNil(preview)
        
        do {
            try await service.processCredential(with: preview as! CredentialPreviewInfo)
        }
        catch let error {
            XCTAssertNotNil(error)
        }
    }
    
    /// Tests the initiation of the `WalletService` and delete a credential.
    func testDeleteCredential() async throws {
        // Given, Where
        var wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        wallet.credentials = try await service.retrieveCredentials()
        
        // Mock the request using the credential id.
        let count = wallet.credentials.count
        let id = wallet.credentials[0].type.id
        let url = URL(string: "https://127.0.0.1:9720/diagency/v1.0/diagency/credentials/\(id)")!
                
        MockURLProtocol.urls[url] = MockHTTPResponse(response: HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "no-data")
                
        try await service.deleteCredential(with: id)
        
        // Then
        wallet.credentials.removeAll { item in
            item.type.id == id
        }
            
        // Then
        XCTAssertEqual(wallet.credentials.count, count - 1)
    }
    
    /// Tests the initiation of the `WalletService` and encode and decodes a wallet.
    func testWalletCodable() async throws {
        // Given, Where
        var wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        wallet.credentials = try await service.retrieveCredentials()
        let result = try JSONEncoder().encode(wallet)
        XCTAssertNotNil(result)
            
        // Then
        let wallet2 = try JSONDecoder().decode(Wallet.self, from: result)
        XCTAssertNotNil(wallet2)
        
        // Then
        // Compare
        XCTAssertEqual(wallet.baseUri, wallet2.baseUri)
        XCTAssertEqual(wallet.refreshUri, wallet2.refreshUri)
        XCTAssertEqual(wallet.clientId, wallet2.clientId)
        XCTAssertEqual(wallet.clientSecret, wallet2.clientSecret)
        XCTAssertEqual(wallet.token, wallet2.token)
        XCTAssertEqual(wallet.agent.id, wallet2.agent.id)
        XCTAssertEqual(wallet.invitations.count, wallet2.invitations.count)
        XCTAssertEqual(wallet.connections.count, wallet2.connections.count)
        XCTAssertEqual(wallet.credentials.count, wallet2.credentials.count)
    }
    
    // MARK: Proof Requests
    
    /// Tests the initiation of the `WalletService` and retrieve inbound proof requests.
    func testInitiateWithProofRequestsInbound() async throws {
        // Given, Where
        let wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken,
                                    refreshUri: wallet.refreshUri,
                                    baseUri: wallet.baseUri,
                                    clientId: wallet.clientId,
                                    certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        let proofRequests = try await service.retrieveProofRequests(filter: .inboundProofRequest)
        XCTAssertTrue(proofRequests.count >= 0)
    }
    
    /// Tests the initiation of the `WalletService` and retrieve passed verifications.
    func testInitiateWithProofRequestsPassed() async throws {
        // Given, Where
        let verificationFilterUrl = URL(string: "https://127.0.0.1:9720/diagency/v1.0/diagency/verifications?state=passed")!
        MockURLProtocol.urls[verificationFilterUrl] = MockHTTPResponse(response: HTTPURLResponse(url: verificationFilterUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "user.verification-proofs-mixed")
        
        let wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        let proofRequests = try await service.retrieveProofRequests()
        XCTAssertTrue(proofRequests.count >= 0)
    }
    
    /// Tests the initiation of the `WalletService` and retrieve passed verifications but no data.
    func testInitiateWithProofRequestsError() async throws {
        // Given, Where
        let verificationFilterUrl = URL(string: "https://127.0.0.1:9720/diagency/v1.0/diagency/verifications?state=passed")!
        MockURLProtocol.urls[verificationFilterUrl] = MockHTTPResponse(response: HTTPURLResponse(url: verificationFilterUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "no-data")
        
        let wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        do {
            let proofRequests = try await service.retrieveProofRequests()
        }
        catch let error {
            XCTAssertNotNil(error)
        }
    }
    
    /// Tests the initiation of the `WalletService` and retrieve passed verifications but invalid data.
    func testInitiateWithProofRequestsInvalid() async throws {
        // Given, Where
        MockURLProtocol.urls[verificationFilterUrl] = MockHTTPResponse(response: HTTPURLResponse(url: verificationFilterUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "user.agent.info-invalid")
        
        let wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        do {
            let _ = try await service.retrieveProofRequests(filter: .inboundProofRequest)
        }
        catch let error {
            XCTAssertNotNil(error)
        }
    }
    
    /// Tests the initiation of the `WalletService` and retrieve inbound proof requests but failed no data.
    func testInitiateWithProofRequestsFailed() async throws {
        // Given
        MockURLProtocol.urls[verificationFilterUrl] = MockHTTPResponse(response: HTTPURLResponse(url: verificationFilterUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "no-data")
        
        // Where
        let wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        do {
            let _ = try await service.retrieveProofRequests()
        }
        catch let error {
            XCTAssertNotNil(error)
        }
    }
    
    /// Tests the initiation of the `WalletService` and create a initation verification preview in JSON-LD format.
    func testInitiateWithInvitationVerificationPreviewJSONLD() async throws {
        // Given
        MockURLProtocol.urls[credentialPreviewUrl] = MockHTTPResponse(response: HTTPURLResponse(url: credentialPreviewUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "user.invitation-processor-verification-jsonld")
        
        // Where
        let wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        let preview = try await service.previewInvitation(using: scanResultPreview)

        
        // Then
        XCTAssertNotNil(preview)
        
        // Then
        XCTAssertNotNil(preview.jsonRepresentation)
    }
    
    /// Tests the initiation of the `WalletService` and create a initation verification preview in Indy  format.
    func testInitiateWithInvitationVerificationPreviewIndy() async throws {
        // Given
        MockURLProtocol.urls[credentialPreviewUrl] = MockHTTPResponse(response: HTTPURLResponse(url: credentialPreviewUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "user.invitation-processor-verification-indy")
        
        // Where
        let wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        let preview = try await service.previewInvitation(using: scanResultPreview)
        
        // Then
        XCTAssertNotNil(preview)
        
        // Then
        XCTAssertNotNil(preview.jsonRepresentation)
    }
    
    /// Tests the initiation of the `WalletService` and create a initation verification preview in mDoc format.
    func testInitiateWithInvitationVerificationPreviewMDoc() async throws {
        // Given
        MockURLProtocol.urls[credentialPreviewUrl] = MockHTTPResponse(response: HTTPURLResponse(url: credentialPreviewUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "user.invitation-processor-verification-mdoc")
        
        // Where
        let wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        let preview = try await service.previewInvitation(using: scanResultPreview)
        
        // Then
        XCTAssertNotNil(preview)
        
        // Then
        XCTAssertNotNil(preview.jsonRepresentation)
    }
    
    /// Tests the initiation of the `WalletService` preview the verification and share proof.
    func testInitiateWithVerificationPreviewAcceptMDoc() async throws {
        // Given
        MockURLProtocol.urls[credentialPreviewUrl] = MockHTTPResponse(response: HTTPURLResponse(url: credentialPreviewUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "user.invitation-processor-verification-mdoc")
        
        MockURLProtocol.urls[verificationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: verificationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "prover.verification-passed-mdoc")
        
        // Where
        let wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        service.delegate = self
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        let preview = try await service.previewInvitation(using: scanResultPreview)
        
        // Then
        XCTAssertNotNil(preview)
        
        do {
            try await service.processProofRequest(with: preview as! VerificationPreviewInfo)
        }
        catch let error {
            XCTAssertNil(error)
        }
    }
    
    /// Tests the initiation of the `WalletService` preview the verification and share proof.
    func testInitiateWithVerificationPreviewAcceptJSONLD() async throws {
        // Given
        MockURLProtocol.urls[credentialPreviewUrl] = MockHTTPResponse(response: HTTPURLResponse(url: credentialPreviewUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "user.invitation-processor-verification-jsonld")
        
        MockURLProtocol.urls[verificationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: verificationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "prover.verification-passed-jsonld")
        
        // Where
        let wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        service.delegate = self
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        let preview = try await service.previewInvitation(using: scanResultPreview)
        
        // Then
        XCTAssertNotNil(preview)
        
        do {
            try await service.processProofRequest(with: preview as! VerificationPreviewInfo)
        }
        catch let error {
            XCTAssertNil(error)
        }
    }
    
    /// Tests the initiation of the `WalletService` preview the verification and share proof.
    func testInitiateWithVerificationPreviewAcceptIndy() async throws {
        // Given
        MockURLProtocol.urls[credentialPreviewUrl] = MockHTTPResponse(response: HTTPURLResponse(url: credentialPreviewUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "user.invitation-processor-verification-indy")
        
        MockURLProtocol.urls[verificationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: verificationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "prover.verification-passed-indy")
        
        // Where
        let wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        service.delegate = self
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        let preview = try await service.previewInvitation(using: scanResultPreview)
        
        // Then
        XCTAssertNotNil(preview)
        
        do {
            try await service.processProofRequest(with: preview as! VerificationPreviewInfo)
        }
        catch let error {
            XCTAssertNil(error)
        }
    }
    
    /// Tests the initiation of the `WalletService` preview the verification and share proof.
    func testInitiateWithVerificationPreviewShare() async throws {
        // Given
        MockURLProtocol.urls[credentialPreviewUrl] = MockHTTPResponse(response: HTTPURLResponse(url: credentialPreviewUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "user.invitation-processor-verification-indy")
        
        MockURLProtocol.urls[verificationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: verificationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "prover.verification-passed-indy")
        
        // Where
        let wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        service.delegate = self
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        let preview = try await service.previewInvitation(using: scanResultPreview)
        
        // Then
        XCTAssertNotNil(preview)
        
        do {
            try await service.processProofRequest(with: preview as! VerificationPreviewInfo, action: .share)
        }
        catch let error {
            XCTAssertNil(error)
        }
    }
    
    /// Tests the initiation of the `WalletService` preview the verification and share proof.
    func testInitiateWithVerificationPreviewShareFailed() async throws {
        // Given
        MockURLProtocol.urls[credentialPreviewUrl] = MockHTTPResponse(response: HTTPURLResponse(url: credentialPreviewUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "user.invitation-processor-verification-indy")
        
        MockURLProtocol.urls[verificationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: verificationUrl, statusCode: 400, httpVersion: nil, headerFields: nil)!, fileResource: "prover.verification-failed")
        
        // Where
        let wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        service.delegate = self
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        let preview = try await service.previewInvitation(using: scanResultPreview)
        
        // Then
        XCTAssertNotNil(preview)
        
        do {
            try await service.processProofRequest(with: preview as! VerificationPreviewInfo, action: .share)
        }
        catch WalletError.verificationFailed(let message) {
            XCTAssertNotNil(message)
        }
        catch let error {
            XCTAssertNotNil(error)
        }
    }
    
    /// Tests the initiation of the `WalletService` preview the verification and rejecting the proof.
    func testInitiateWithVerificationPreviewReject() async throws {
        // Given
        MockURLProtocol.urls[credentialPreviewUrl] = MockHTTPResponse(response: HTTPURLResponse(url: credentialPreviewUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "user.invitation-processor-verification-mdoc")
        
        MockURLProtocol.urls[verificationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: verificationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "prover.verification-passed-mdoc")
        
        // Where
        let wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        service.delegate = self
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        let preview = try await service.previewInvitation(using: scanResultPreview)
        
        // Then
        XCTAssertNotNil(preview)
        
        do {
            try await service.processProofRequest(with: preview as! VerificationPreviewInfo, action: .reject)
        }
        catch let error {
            XCTAssertNil(error)
        }
    }
    
    /// Tests the initiation of the `WalletService` preview the verification and share proof throwing an error.
    func testInitiateWithVerificationPreviewError() async throws {
        // Given
        MockURLProtocol.urls[credentialPreviewUrl] = MockHTTPResponse(response: HTTPURLResponse(url: credentialPreviewUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "user.invitation-processor-verification-mdoc")
        
        MockURLProtocol.urls[verificationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: verificationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "no-data")
        
        // Where
        let wallet = try await initiateWallet()
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let service = WalletService(token: wallet.token.accessToken, refreshUri: wallet.refreshUri, baseUri: wallet.baseUri, clientId: wallet.clientId, certificateTrust: ignoreSSLCertificate ? SelfSignedCertificateDelegate() : nil)
        service.delegate = self
        
        // Then
        XCTAssertNotNil(service)
        
        // Then
        let preview = try await service.previewInvitation(using: scanResultPreview)
        
        // Then
        XCTAssertNotNil(preview)
        
        do {
            try await service.processProofRequest(with: preview as! VerificationPreviewInfo)
        }
        catch let error {
            XCTAssertNotNil(error)
        }
    }
}

extension WalletServiceTest: WalletServiceDelegate {
    func walletService(service: WalletService, didVerifyCredential verification: VerificationInfo) {
        XCTAssertNotNil(verification)
    }
    
    func walletService(service: WalletService, didGenerateProof verification: VerificationInfo) {
        XCTAssertNotNil(verification)
    }
    
    func walletService(service: WalletService, didAcceptCredential credential: Credential) {
        XCTAssertNotNil(credential)
    }
}
