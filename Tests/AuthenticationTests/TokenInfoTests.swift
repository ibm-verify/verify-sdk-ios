//
// Copyright contributors to the IBM Verify Authentication SDK for iOS project
//

import XCTest
import Foundation
import Core
@testable import Authentication

class TokenInfoTests: XCTestCase {
    let urlBase = "https://sdk.verify.ibm.com/v1.0/endpoint/default/token"
    
    override func setUp() {
        super.setUp()
        URLProtocol.registerClass(MockURLProtocol.self)
    }

    override func tearDown() {
        super.tearDown()
        URLProtocol.unregisterClass(MockURLProtocol.self)
    }

    /// Decodes the `TokenInfo`
    func testDecodeTokenExpiresIn() throws {
        // Given
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .formatted(.iso8061FormatterBehavior)
        
        // Where
        let token = try decoder.decode(TokenInfo.self, from: tokenJson.data(using: .utf8)!)
        
        // Then
        XCTAssertNotNil(token, "Decoded token success")
        XCTAssertEqual(token.accessToken, "a1b2c3d4")
        XCTAssertEqual(token.refreshToken, "h5j6i7k8")
        XCTAssertEqual(token.expiresIn, 7200)
        XCTAssertEqual(token.scope, "name age")
    }
    
    /// Decodes the `TokenInfo`
    func testDecodeTokenExpires_In() throws {
        // Given
        let decoder = JSONDecoder()
        
        // Where
        let token = try decoder.decode(TokenInfo.self, from: tokenJson2.data(using: .utf8)!)
        
        // Then
        XCTAssertNotNil(token, "Decoded token success")
        XCTAssertEqual(token.accessToken, "a1b2c3d4")
        XCTAssertEqual(token.refreshToken, "h5j6i7k8")
        XCTAssertEqual(token.expiresIn, 7200)
        XCTAssertEqual(token.scope, "name age")
    }
    
    /// Decodes the `TokenInfo`
    func testDecodeTokenExpiresOn() throws {
        // Given
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .formatted(.iso8061FormatterBehavior)
        
        // Where
        let token = try decoder.decode(TokenInfo.self, from: tokenJson4.data(using: .utf8)!)
        
        // Then
        XCTAssertNotNil(token, "Decoded token success")
        print(token)
    }
    
    /// Decodes the `TokenInfo` from it's basic OAuth persisted format.
    func testDecodeTokenBasic() throws {
        // Given
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .formatted(.iso8061FormatterBehavior)
        
        // Where
        let token = try decoder.decode(TokenInfo.self, from: tokenJson1.data(using: .utf8)!)
        
        // Then
        XCTAssertNotNil(token, "Decoded token success")
        XCTAssertEqual(token.accessToken, "a1b2c3d4")
        XCTAssertEqual(token.refreshToken, "h5j6i7k8")
        XCTAssertEqual(token.tokenType, "Bearer")
        XCTAssertEqual(token.expiresIn, 7200)
    }
    
    /// Decodes the `TokenInfo`
    func testDecodeTokenAdditionalData() throws {
        // Given
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .formatted(DateFormatter.iso8061FormatterBehavior)
        
        // Where
        let token = try decoder.decode(TokenInfo.self, from: tokenJson3.data(using: .utf8)!)
        
        // Then
        XCTAssertNotNil(token, "Decoded token success")
        XCTAssertEqual(token.accessToken, "a1b2c3d4")
        XCTAssertEqual(token.refreshToken, "h5j6i7k8")
        XCTAssertEqual(token.expiresIn, 3599)
        XCTAssertEqual(token.scope, "name age")
        XCTAssertEqual(token.additionalData.count, 2)
        
        // Test expiresOn date.
        let dateFormatter = DateFormatter.iso8061FormatterBehavior
        let expiresOn = dateFormatter.date(from: "2022-12-30T11:30:31.340Z")
        XCTAssertEqual(token.expiresOn, expiresOn!)
    }
    
    /// Decodes the `TokenInfo` and checks the `expiresIn`.
    func testTokenExpired() throws {
        // Given
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .formatted(.iso8061FormatterBehavior)
        
        // Where
        let token = try decoder.decode(TokenInfo.self, from: tokenJson.data(using: .utf8)!)
        
        // Then
        XCTAssertNotNil(token, "Decoded token success")
        XCTAssertTrue(token.tokenExpired)
    }
    
    /// Decodes the `TokenInfo` and checks the `shoudRefresh`.
    func testTokenShouldRefresh() throws {
        // Given
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .formatted(.iso8061FormatterBehavior)
        
        // Where
        let token = try decoder.decode(TokenInfo.self, from: tokenJson.data(using: .utf8)!)
        
        // Then
        XCTAssertNotNil(token, "Decoded token success")
        XCTAssertTrue(token.shouldRefresh)
    }
    
    /// Decodes the `TokenInfo` twice and checks to equality.
    func testTokenIsEqual() throws {
        // Given
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .formatted(.iso8061FormatterBehavior)
        
        // Where
        let token1 = try decoder.decode(TokenInfo.self, from: tokenJson.data(using: .utf8)!)
        let token2 = try decoder.decode(TokenInfo.self, from: tokenJson.data(using: .utf8)!)
        
        // Then
        XCTAssertEqual(token1, token2)
    }
    
    /// Decodes the `TokenInfo` and create the request authorization header value.
    func testTokenHeader() throws {
        // Given
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .formatted(.iso8061FormatterBehavior)
        let headerValue = "Bearer a1b2c3d4"
        
        // Where
        let token = try decoder.decode(TokenInfo.self, from: tokenJson.data(using: .utf8)!)
        
        // Then
        XCTAssertNotNil(token, "Decoded token success")
        XCTAssertEqual(token.authorizationHeader, headerValue)
    }

    /// Encodes the `TokenInfo`.
    func testEncodeToken() async throws {
        // Given
        let tokenUrl = URL(string: urlBase)!
        MockURLProtocol.urls[tokenUrl] = MockResponse(response: HTTPURLResponse(url: tokenUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, data: tokenJson2.data(using: .utf8)!)
        
        // Where
        var token: TokenInfo?
        let provider = OAuthProvider(clientId: "clientId", clientSecret: "clientSecret", additionalParameters: ["pet": "dog", "food": "pizza"])
        provider.timeoutInterval = 10
       
        // Then
        do {
            token = try await provider.authorize(issuer: tokenUrl, username: "username", password: "password", scope: ["name", "age"])
            XCTAssertNotNil(token)
        }
        catch let error {
            print(error)
            XCTFail(error.localizedDescription)
        }
        
        // Then
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        
        let data = try encoder.encode(token)
        print(String(data: data, encoding: .utf8)!)
    }
    
    /// Encodes the `TokenInfo`.
    func testEncodeTokenDate() async throws {
        // Given
        let tokenUrl = URL(string: urlBase)!
        MockURLProtocol.urls[tokenUrl] = MockResponse(response: HTTPURLResponse(url: tokenUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, data: tokenJson2.data(using: .utf8)!)
        
        // Where
        var token: TokenInfo?
        let provider = OAuthProvider(clientId: "clientId", clientSecret: "clientSecret", additionalParameters: ["displayName": "John Citizen", "deviceId": "uuidbc1f1f5e-5ffa-4595-9d4e-0a43cd225781"])
        provider.timeoutInterval = 10
       
        // Then
        do {
            token = try await provider.authorize(issuer: tokenUrl, username: "username", password: "password", scope: ["name", "age"])
            XCTAssertNotNil(token)
        }
        catch let error {
            print(error)
            XCTFail(error.localizedDescription)
        }
        
        // Then
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .formatted(DateFormatter.iso8061FormatterBehavior)
        encoder.outputFormatting = .prettyPrinted
        
        let data = try encoder.encode(token)
        print(String(data: data, encoding: .utf8)!)
    }
}


let tokenJson = """
{
    "token_type" : "Bearer",
    "scope" : "name age",
    "refreshToken" : "h5j6i7k8",
    "grant_id" : "b49cf0c8add0",
    "accessToken" : "a1b2c3d4",
    "expires_on": "2022-12-30T11:30:31.340Z",
    "expiresIn" : 7200
}
"""

let tokenJson1 = """
{
    "tokenType" : "Bearer",
    "refreshToken" : "h5j6i7k8",
    "accessToken" : "a1b2c3d4",
    "expiresOn": "2022-12-30T11:30:31.340Z",
    "expiresIn" : 7200
}
"""

let tokenJson2 = """
{
    "token_type" : "Bearer",
    "scope" : "name age",
    "refreshToken" : "h5j6i7k8",
    "grant_id" : "b49cf0c8add0",
    "accessToken" : "a1b2c3d4",
    "expires_in" : 7200
}
"""

let tokenJson3 = """
{
    "deviceId": "uuidbc1f1f5e-5ffa-4595-9d4e-0a43cd225781",
    "token_type": "bearer",
    "scope" : "name age",
    "refreshToken": "h5j6i7k8",
    "displayName": "John Citizen",
    "expiresIn": 3599,
    "accessToken": "a1b2c3d4",
    "expires_on": "2022-12-30T11:30:31.340Z",
    "expires_in" : 7200
}
"""

let tokenJson4 = """
{
      "authenticator_id": "uuid32f7aa4f-6de3-4f6a-b242-a2d935144974",
      "token_type": "bearer",
      "scope": "mmfaAuthn",
      "refreshToken": "VM6eEnMxmr8n479QSXiy1fTiVXP552StZNoD7GJr",
      "display_name": "mhm",
      "expiresIn": 3599,
      "accessToken": "TCvJksf2wdIF5k9pFS2x",
      "expires_on": "2023-01-03T06:32:51.632Z"
}
"""
