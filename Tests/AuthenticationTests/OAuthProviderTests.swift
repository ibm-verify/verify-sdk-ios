//
// Copyright contributors to the IBM Verify Authentication SDK for iOS project
//

import XCTest
import Foundation
@testable import Authentication
@testable import Core

class OAuthProviderTest: XCTestCase {
    // TODO: Replace these credential parameters with valid values.
    let clientId = "38cdeff8-9693-4f0b-99c9-563d5c20d6a7"
    let clientSecret = ""
    let username = "testuser"
    let password = "Passw0rd"
    let urlBase = "https://sdk.verify.ibm.com/v1.0/endpoint/default"
    
    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    // MARK: - Discovery
    
    /// Tests the disovery endpoint against a publically OAuth 2 endpoint.
    func testDiscover() async throws {
        // Given
       let url = URL(string: "\(urlBase)/.well-known/openid-configuration")!
        
        // Where, Then
        do {
            let result = try await OAuthProvider.discover(issuer: url)
            XCTAssertNotNil(result)
            XCTAssert(true)
        }
        catch let error {
            print(error)
            XCTFail(error.localizedDescription)
        }
    }
    
    func testInvalidDiscover() async throws {
        // Given
        let url = URL(string: "\(urlBase)/.well-known")!
        
        // Where, Then
        do {
            let _ = try await OAuthProvider.discover(issuer: url)
        }
        catch let error {
            print(error)
            XCTAssertNotNil(error)
            XCTAssertTrue(true, "The .well-known endpoint metadata shouldn't be returned.")
        }
    }

    // MARK: - Authorize
    
    /// Tests the token endpoint for obtaining an access token using ROPC.
    func testAuthorizeROPC() async throws {
        // Given
        let url = URL(string: "\(urlBase)/token")!
        
        // Where
        let provider = OAuthProvider(clientId: self.clientId, clientSecret: self.clientSecret, additionalParameters: ["pet": "dog", "food": "pizza"])
        provider.timeoutInterval = 10
       
        // Then
        do {
            let token = try await provider.authorize(issuer: url, username: self.username, password: self.password, scope: ["name", "age"])
            XCTAssertNotNil(token)
        }
        catch let error {
            print(error)
            XCTFail(error.localizedDescription)
        }
    }
    
    /// Tests the token endpoint for obtaining an access token and ID token using ROPC.
    func testAuthorizeROPCIDToken() async throws {
        // Given
        let url = URL(string: "\(urlBase)/token")!
        
        // Where
        let provider = OAuthProvider(clientId: self.clientId, clientSecret: self.clientSecret, additionalParameters: ["pet": "dog", "food": "pizza"])
        provider.timeoutInterval = 10
       
        // Then
        do {
            let token = try await provider.authorize(issuer: url, username: self.username, password: self.password, scope: ["openid", "name", "age"])
            print(token)
            XCTAssertNotNil(token)
            XCTAssertNotNil(token.idToken)
        }
        catch let error {
            print(error)
            XCTFail(error.localizedDescription)
        }
    }
    
    /// Tests the token endpoint for obtaining an access token and ID token using ROPC.
    func testAuthorizeROPCIDTokenWithHeaders() async throws {
        // Given
        let url = URL(string: "\(urlBase)/token")!
        
        // Where
        let provider = OAuthProvider(clientId: self.clientId, clientSecret: self.clientSecret, additionalParameters: ["pet": "dog", "food": "pizza"])
        provider.additionalHeaders = ["foo": "bar"]
        provider.timeoutInterval = 10
       
        // Then
        do {
            let token = try await provider.authorize(issuer: url, username: self.username, password: self.password, scope: ["openid", "name", "age"])
            print(token)
            XCTAssertNotNil(token)
            XCTAssertNotNil(token.idToken)
        }
        catch let error {
            print(error)
            XCTFail(error.localizedDescription)
        }
    }
    
    /// Tests the token endpoint for obtaining an access token using ROPC which generates a grant_id
    func testAuthorizeWithParametersResponse() async throws {
        // Given
        let url = URL(string: "\(urlBase)/token")!
        
        // Where
        let provider = OAuthProvider(clientId: self.clientId, clientSecret: self.clientSecret)
        provider.timeoutInterval = 10
       
        // Then
        do {
            let token = try await provider.authorize(issuer: url, username: self.username, password: self.password)
            XCTAssertNotNil(token)
            XCTAssertNotNil(token.additionalData)
            XCTAssertTrue(token.additionalData.contains { return $0.key == "grant_id" })
        }
        catch let error {
            print(error)
            XCTFail(error.localizedDescription)
        }
    }
    
    /// Tests the token endpoint for obtaining an access token using ROPC.
    func testAuthorizeWithScope() async throws {
        // Given
        let url = URL(string: "\(urlBase)/token")!
        
        // Where
        let provider = OAuthProvider(clientId: self.clientId, clientSecret: self.clientSecret)
        provider.timeoutInterval = 10
       
        // Then
        do {
            let token = try await provider.authorize(issuer: url, username: self.username, password: self.password, scope: ["name", "age"])
                XCTAssertNotNil(token)
                XCTAssertNotNil(token.scope)
                XCTAssertEqual(token.scope, "name age")
        }
        catch let error {
            XCTFail(error.localizedDescription)
        }
    }
    
    /// Tests the token endpoint for obtaining refresh of an access token.
    func testAuthorizeRefresh() async throws {
        // Given
        let url = URL(string: "\(urlBase)/token")!
        
        // Where
        let scopes = ["name", "age"]
        let provider = OAuthProvider(clientId: self.clientId, clientSecret: self.clientSecret, additionalParameters: ["pet": "dog", "food": "pizza"])
        provider.timeoutInterval = 10

        
        do {
            // Then
            let token = try await provider.authorize(issuer: url, username: self.username, password: self.password, scope: scopes)
            print(token)
            XCTAssertNotNil(token)
        
            // Then

            let newToken = try await provider.refresh(issuer: url, refreshToken: token.refreshToken ?? "", scope: scopes)
                print(newToken)
                XCTAssertNotEqual(newToken, token)
        }
        catch let error {
            XCTFail(error.localizedDescription)
        }
    }
    
    /// Tests the token endpoint for obtaining refresh using an invalid refresh token.
    func testAuthorizeInValidRefreshToken() async throws {
        // Given
        let url = URL(string: "\(urlBase)/token")!
        
        // Where
        let scopes = ["name", "age"]
        let provider = OAuthProvider(clientId: self.clientId, clientSecret: self.clientSecret, additionalParameters: ["pet": "dog", "food": "pizza"])
        provider.timeoutInterval = 10

        do {
            // Then
            let token = try await provider.authorize(issuer: url, username: self.username, password: self.password, scope: scopes)
            print(token)
            XCTAssertNotNil(token)
        
            // Then

            let newToken = try await provider.refresh(issuer: url, refreshToken: "ABC123", scope: scopes)
                print(newToken)
                XCTAssertNotEqual(newToken, token)
        }
        catch let error {
            XCTAssertNotNil(error, error.localizedDescription)
        }
    }
    
    
    /// Tests the token endpoint for obtaining an access token from an AZN codel
    func testAuthorizeCodeFlow() async throws {
        // Given
        let tokenUrl = URL(string: "\(urlBase)/token")!
        MockURLProtocol.urls[tokenUrl] = MockResponse(response: HTTPURLResponse(url: tokenUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, data: tokenJson.data(using: .utf8)!)
        
        // Where
        let scopes = ["name", "age"]
        let provider = OAuthProvider(clientId: self.clientId, clientSecret: self.clientSecret, additionalParameters: ["pet": "dog", "food": "pizza"])
        provider.timeoutInterval = 10

        do {
            // Then
            let token = try await provider.authorize(issuer: tokenUrl, redirectUrl: URL(string: "https://localhost:3000")!, authorizationCode: "abc123", codeVerifier: "xyz987", scope: scopes)
            print(token)
            XCTAssertNotNil(token)
        
            // Then
            XCTAssertNotNil(token)
        }
        catch let error {
            XCTAssertNotNil(error, error.localizedDescription)
        }
    }
}

