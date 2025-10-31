//
// Copyright contributors to the IBM Verify DC SDK for iOS project
//

import XCTest
import Core
import Authentication
@testable import DC

class WalletProviderTests: XCTestCase {
    let scanResultRegister = """
    {
        "serviceBaseUrl": "https://127.0.0.1:9720/diagency",
        "oauthBaseUrl": "https://127.0.0.1:8436/oauth2"
    }
    """
    
    let clientId = "onpremise_vcholders"
    let accessToken = "abc123"
    let refreshToken = "bcd234"
    
    let tokenUrl = URL(string: "https://127.0.0.1:8436/oauth2/token")!
    let agentUrl = URL(string: "https://127.0.0.1:9720/diagency/v1.0/diagency/info")!
    let connectionsUrl = URL(string: "https://127.0.0.1:9720/diagency/v1.0/diagency/connections")!
    let credentialsUrl = URL(string: "https://127.0.0.1:9720/diagency/v1.0/diagency/credentials?filter=%7B%22state%22:%22stored%22%7D")!
    let invitationsUrl = URL(string: "https://127.0.0.1:9720/diagency/v1.0/diagency/invitations")!
    
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
    }

    override func tearDownWithError() throws {
        try super.tearDownWithError()
        URLProtocol.unregisterClass(MockURLProtocol.self)
    }

    // MARK: Wallet Provider
    
    /// Tests the initiation of the `WalletProvider` from token info..
    func testInitiateWalletProviderWithTokenInfo() async throws {
        // Given
        let provider = WalletProvider(json: scanResultRegister, ignoreSSLCertificate: ignoreSSLCertificate)
        
        let oAuthProvider = OAuthProvider(clientId: clientId)
        let token = try await oAuthProvider.authorize(issuer: tokenUrl , username: "user", password: "password")
        
        // Where
        let wallet = try await provider.register(with: "John", clientId: clientId, token: token)
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        XCTAssertNotNil(wallet.agent)
        XCTAssertNotNil(wallet.connections)
        XCTAssertNotNil(wallet.invitations)
        XCTAssertNotNil(wallet.credentials)
    }
    
    /// Tests the initiation of the `WalletProvider` from token attributes.
    func testInitiateWalletProviderWithAttributes() async throws {
        // Given
        let provider = WalletProvider(json: scanResultRegister, ignoreSSLCertificate: ignoreSSLCertificate)
        
        let oAuthProvider = OAuthProvider(clientId: clientId)
        let token = try await oAuthProvider.authorize(issuer: tokenUrl , username: "user", password: "password")
        
        // Where
        let wallet = try await provider.register(with: "John", clientId: clientId, accessToken: token.accessToken, refreshToken: token.refreshToken, expiresIn: token.expiresIn)
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        XCTAssertNotNil(wallet.agent)
        XCTAssertNotNil(wallet.connections)
    }
    
    /// Tests the initiation of the `WalletProvider` from default token attributes.
    func testInitiateWalletProviderWithDefaltAttributes() async throws {
        // Given
        let provider = WalletProvider(json: scanResultRegister, ignoreSSLCertificate: ignoreSSLCertificate)
        
        // Where
        let wallet = try await provider.register(with: "John", clientId: "abc123", accessToken: "bcd234")
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        XCTAssertNotNil(wallet.agent)
        XCTAssertNotNil(wallet.connections)
    }
    
    /// Tests a failed initiation of the `WalletProvider` from JSON.
    func testInitiateWalletProviderFailed() async throws {
        // Given
        let provider = WalletProvider(json: "nojson", ignoreSSLCertificate: ignoreSSLCertificate)
        var thrownError: Error?
        
        // Where
        do {
            _ = try await provider.register(with: "John", clientId: "abc123", accessToken: "bcd234", refreshToken: "def345")
        }
        catch {
            thrownError = error
        }
        
        // Then
        XCTAssertNotNil(thrownError)
    }
    
    /// Tests the initiation of the `WalletProvider` from JSON with the `TokenInfo`.
    func testInitiateWalletProviderWithToken() async throws {
        // Given
        let provider = WalletProvider(json: scanResultRegister, ignoreSSLCertificate: ignoreSSLCertificate)
        
        let json = """
        {
            "refreshToken": "def345",
            "accessToken": "bcd234",
            "expiresIn": 3600,
        }
        """.data(using: .utf8)!
        
        let token = try JSONDecoder().decode(TokenInfo.self, from: json)
        
        // Where
        let wallet = try await provider.register(with: "John", clientId: "abc123", token: token)
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let agent = wallet.agent
        XCTAssertNotNil(agent)
    }
    
    /// Tests the initiation of the `WalletProvider` from JSON with the push token.
    func testInitiateWalletProviderWithPushToken() async throws {
        // Given
        let provider = WalletProvider(json: scanResultRegister, ignoreSSLCertificate: ignoreSSLCertificate)
        
        // Where
        let wallet = try await provider.register(with: "John", clientId: "abc123", accessToken: "bcd234", refreshToken: "def345", pushToken: "efg456")
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        let agent = wallet.agent
        XCTAssertNotNil(agent)
    }
    
    /// Tests the initiation of the `WalletProvider` failing with no valid certificate.
    func testInitiateProviderHttpsError() async throws {
        // Given
        let provider = WalletProvider(json: scanResultRegister, ignoreSSLCertificate: true)
        var thrownError: Error?
        
        // Where
        do {
            _ = try await provider.register(with: "John", clientId: "abc123", accessToken: "bcd234", refreshToken: "def345")
        }
        catch {
            thrownError = error
        }
        
        // Then
        XCTAssertNotNil(thrownError)
    }
    
    // MARK: Wallet Error
    
    /// Tests the `WalletError` equatable.
    func testWalletErrorEquatable() async throws {
        // Given
        let error1 = WalletError.dataInitializationFailed
        let error2 = WalletError.dataInitializationFailed
        let error3 = WalletError.failedToParse
        
        // Where, Then
        XCTAssertEqual(error1, error2)
        
        // Then
        XCTAssertEqual(error2, error2)
        
        // Then
        XCTAssertNotEqual(error2, error3)
    }
    
    // MARK: Wallet Collections
    
    /// Tests the initiation of the `WalletProvider` from JSON remove connection item.
    func testWalletRemoveConnectionItem() async throws {
        // Given
        let provider = WalletProvider(json: scanResultRegister, ignoreSSLCertificate: ignoreSSLCertificate)
        
        // Where
        var wallet = try await provider.register(with: "John", clientId: "abc123", accessToken: "bcd234", refreshToken: "def345")
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        if wallet.connections.count > 0 {
            wallet.connections.remove(at: 0)
        }
        
        // Then
        XCTAssertTrue(wallet.connections.count >= 0)
    }
    
    /// Tests the initiation of the `WalletProvider` from JSON remove invitation item.
    func testWalletRemoveInvitationItem() async throws {
        // Given
        let provider = WalletProvider(json: scanResultRegister, ignoreSSLCertificate: ignoreSSLCertificate)
        
        // Where
        var wallet = try await provider.register(with: "John", clientId: "abc123", accessToken: "bcd234", refreshToken: "def345")
        
        // Then
        XCTAssertNotNil(wallet)
        
        // Then
        if wallet.invitations.count > 0 {
            wallet.invitations.remove(at: 0)
        }
        
        // Then
        XCTAssertTrue(wallet.invitations.count >= 0)
    }
    
    /// Tests the failed initiation of the `WalletProvider` from JSON on agent.
    func testWalletFailedAgentParse() async throws {
        // Given
        MockURLProtocol.urls[agentUrl] = MockHTTPResponse(response: HTTPURLResponse(url: agentUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "user.agent.info-invalid")
        let provider = WalletProvider(json: scanResultRegister, ignoreSSLCertificate: ignoreSSLCertificate)
        var thrownError: Error?
        
        // Where
        do {
            _ = try await provider.register(with: "John", clientId: "abc123", accessToken: "bcd234", refreshToken: "def345")
        }
        catch {
            thrownError = error
        }
        
        // Then
        XCTAssertNotNil(thrownError)
    }
    
    /// Tests the failed initiation of the `WalletProvider` from JSON on invitation items.
    func testWalletFailedInvitationsParse() async throws {
        // Given
        MockURLProtocol.urls[invitationsUrl] = MockHTTPResponse(response: HTTPURLResponse(url: invitationsUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "user.invitations-invalid")
        let provider = WalletProvider(json: scanResultRegister, ignoreSSLCertificate: ignoreSSLCertificate)
        var thrownError: Error?
        
        // Where
        do {
            _ = try await provider.register(with: "John", clientId: "abc123", accessToken: "bcd234", refreshToken: "def345")
        }
        catch {
            thrownError = error
        }
        
        // Then
        XCTAssertNotNil(thrownError)
    }
    
    /// Tests the failed initiation of the `WalletProvider` from JSON on connection items.
    func testWalletFailedConnectionParse() async throws {
        // Given
        MockURLProtocol.urls[connectionsUrl] = MockHTTPResponse(response: HTTPURLResponse(url: connectionsUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "user.connections-invalid")
        let provider = WalletProvider(json: scanResultRegister, ignoreSSLCertificate: ignoreSSLCertificate)
        var thrownError: Error?
        
        // Where
        do {
            _ = try await provider.register(with: "John", clientId: "abc123", accessToken: "bcd234", refreshToken: "def345")
        }
        catch {
            thrownError = error
        }
        
        // Then
        XCTAssertNotNil(thrownError)
    }
    
    /// Tests the failed initiation of the `WalletProvider` from JSON on credential items.
    func testWalletFailedCredentialParse() async throws {
        // Given
        MockURLProtocol.urls[credentialsUrl] = MockHTTPResponse(response: HTTPURLResponse(url: credentialsUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "user.connections-invalid")
        let provider = WalletProvider(json: scanResultRegister, ignoreSSLCertificate: ignoreSSLCertificate)
        var thrownError: Error?
        
        // Where
        do {
            _ = try await provider.register(with: "John", clientId: "abc123", accessToken: "bcd234", refreshToken: "def345")
        }
        catch {
            thrownError = error
        }
        
        // Then
        XCTAssertNotNil(thrownError)
    }
    
    /// Tests the failed initiation of the `WalletProvider` from JSON on invitation items.
    func testWalletFailedInvitationsNoData() async throws {
        // Given
        MockURLProtocol.urls[invitationsUrl] = MockHTTPResponse(response: HTTPURLResponse(url: invitationsUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "no-data")
        let provider = WalletProvider(json: scanResultRegister, ignoreSSLCertificate: ignoreSSLCertificate)
        var thrownError: Error?
        
        // Where
        do {
            _ = try await provider.register(with: "John", clientId: "abc123", accessToken: "bcd234", refreshToken: "def345")
        }
        catch {
            thrownError = error
        }
        
        // Then
        XCTAssertNotNil(thrownError)
    }
    
    /// Tests the failed initiation of the `WalletProvider` from JSON on connection items.
    func testWalletFailedConnectionNoData() async throws {
        // Given
        MockURLProtocol.urls[connectionsUrl] = MockHTTPResponse(response: HTTPURLResponse(url: connectionsUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "no-data")
        let provider = WalletProvider(json: scanResultRegister, ignoreSSLCertificate: ignoreSSLCertificate)
        var thrownError: Error?
        
        // Where
        do {
            _ = try await provider.register(with: "John", clientId: "abc123", accessToken: "bcd234", refreshToken: "def345")
        }
        catch {
            thrownError = error
        }
        
        // Then
        XCTAssertNotNil(thrownError)
    }
    
    /// Tests the failed initiation of the `WalletProvider` from JSON on credentials items.
    func testWalletFailedCredentialsNoData() async throws {
        // Given
        MockURLProtocol.urls[credentialsUrl] = MockHTTPResponse(response: HTTPURLResponse(url: credentialsUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "no-data")
        let provider = WalletProvider(json: scanResultRegister, ignoreSSLCertificate: ignoreSSLCertificate)
        var thrownError: Error?
        
        // Where
        do {
            _ = try await provider.register(with: "John", clientId: "abc123", accessToken: "bcd234", refreshToken: "def345")
        }
        catch {
            thrownError = error
        }
        
        // Then
        XCTAssertNotNil(thrownError)
    }
}
