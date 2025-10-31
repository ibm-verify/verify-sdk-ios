//
// Copyright contributors to the IBM Verify FIDO2 SDK for iOS project
//

import XCTest
import CryptoKit
@testable import FIDO2

class AttestationStatementProviderTests: XCTestCase {
    // Given
    let base64PrivateKey = "BHl6R2xQg0u2tiT9r6NUliSJ1uCZ4njHLJ/oAcrfR3e9Z/tOLP6qYKuBBCGBOWdJuA9kgSL2akQ5nJgL7FQHssfKDJRASpY11hR47Z6qQ9FuczC2sbTV+J+ZorhemDjW/g=="
    
    let base64Certificate = """
-----BEGIN CERTIFICATE-----
MIIDVjCCAT6gAwIBAgIJALx2ZhFIhvMdMA0GCSqGSIb3DQEBCwUAMC4xCzAJBgNV
BAYTAlVTMQwwCgYDVQQKDANJQk0xETAPBgNVBAMMCEZJRE8yQVBQMB4XDTIxMDMw
MTIyMjY0MVoXDTQ4MDcxNjIyMjY0MVowYDELMAkGA1UEBhMCVVMxDDAKBgNVBAoM
A0lCTTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEfMB0GA1UE
AwwWRklETzJBUFAtUEFDS0VELVNJR05FUjBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABHl6R2xQg0u2tiT9r6NUliSJ1uCZ4njHLJ/oAcrfR3e9Z/tOLP6qYKuBBCGB
OWdJuA9kgSL2akQ5nJgL7FQHssejEDAOMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcN
AQELBQADggIBAASs8HFGmfMAzBX5INkanyuhSNLF1+h/bOOaBO1yOsSgQhHS9lP3
HMN4sP5tX9zOdFs8xue/q1rqiFEZELhgIxioFy1RKSCXYFZar5s0d9JunJJW39DA
Yxfl9N1HtyVGGEAFPJ2xiR/Q8WD2FOZjnk6lzi8jPTQRSurUfzhsk8+YPAn6TzXi
GN61fpl4Z7JQHM8aMXyTB0aZgED/Vx6XftPoNLulOnnj3cnqiG05Xa2lAePU4IQK
GeefVc3B1Y/jQIAqkt6Kf2YgJdTbgmFVYve3o/eBpx5rGJ1wY7VALrJO4btmnaLb
XIOssmkF/lWBy3DBaGy2NCV6GumhEF1DDawXpY+apQLd7VHcVtYCypiV52WkHMZt
FfKyH2bJj42Onf+0yflyI6g+ETC2rx8JiuMzT9AAi6BC0uEbs+JB8PAgJbgfZixA
biz52LbmegqteDD4mR1ElL21US1JzmcwDQ5Z9NLT2XyP5TyfMiaEJrI3G0L2dx14
S0Z20tvS57ZgvS7Ace3k4/WV6hpgCi3yJAfdAeTzYXPPzg5bK54EMfcfHkIo/1bv
4FfkHG7/ffWtaxzYo7l43Nrc6fMMDg2rsGGKl8RJGvzcsqEKsTBmIKeWagxJvZwt
AxQavFL7HGYAdjG7qBMb9+rEC6XY6rsVLbP8hCQ7NjKlsUMCNN/i97X5
-----END CERTIFICATE-----
"""
    
    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    // MARK: SelfAttestation
    
    func testCreateSelfAttestation() throws {
        // Given
        let result = SelfAttestation(UUID())
        
        // Then
        XCTAssertNotNil(result)
    }
    
    func testSelfAttestationStatementThrowPrivateKey() throws {
        // Given
        var result = SelfAttestation(UUID())
        result.authenticatorData = "authenticatorData".data(using: .utf8)
        result.clientDataHash = "clientDataHash".data(using: .utf8)
        
        // Then
        XCTAssertThrowsError(try result.statement(), "SecureEnclave private key not assigned. Error should have been thrown but no Error was thrown") { error in
                 XCTAssertEqual(error as? PublicKeyCredentialError, PublicKeyCredentialError.invalidPrivateKeyData)
        }
    }
    
    func testSelfAttestationStatementThrowData() throws {
        // Given
        let result = SelfAttestation(UUID())
        
        // Then
        XCTAssertThrowsError(try result.statement(), "Attestation data not assigned. Error should have been thrown but no Error was thrown") { error in
                 XCTAssertEqual(error as? PublicKeyCredentialError, PublicKeyCredentialError.invalidAttestationData)
        }
    }
    
    // MARK: BasicAttestation
    
    func testCreateBasicAttestation() throws {
        // Given
        let result = BasicAttestation(UUID(), base64PrivateKey: base64PrivateKey, base64Certificate: base64Certificate)
        
        // Then
        XCTAssertNotNil(result)
    }
    
    func testBasicAttestationStatement() throws {
        // Given
        var result = BasicAttestation(UUID(), base64PrivateKey: base64PrivateKey, base64Certificate: base64Certificate)
        result.authenticatorData = "authenticatorData".data(using: .utf8)
        result.clientDataHash = "clientDataHash".data(using: .utf8)
        
        // Where
        let value = try result.statement()
        
        // Then
        XCTAssertNotNil(value)
        
    }
    
    func testBasicAttestationStatementEx() throws {
        // Given
        var result = BasicAttestation(UUID(), base64PrivateKey: base64PrivateKey, base64Certificate: base64Certificate)
        result.authenticatorData = "authenticatorData".data(using: .utf8)
        result.clientDataHash = "clientDataHash".data(using: .utf8)
        
        // Where
        let value = try result.statement()
        
        // Then
        XCTAssertEqual(value.count, 3)
        
    }
    
    func testBasicAttestationStatementThrowData() throws {
        // Given
        let result = BasicAttestation(UUID(), base64PrivateKey: base64PrivateKey, base64Certificate: base64Certificate)
        
        // Then
        XCTAssertThrowsError(try result.statement(), "Attestation data not assigned. Error should have been thrown but no Error was thrown") { error in
                 XCTAssertEqual(error as? PublicKeyCredentialError, PublicKeyCredentialError.invalidAttestationData)
        }
    }
    
    func testBasicAttestationStatementThrowPrivateKey() throws {
        // Given
        var result = BasicAttestation(UUID(), base64PrivateKey: base64PrivateKey + "abc123", base64Certificate: base64Certificate)
        result.authenticatorData = "authenticatorData".data(using: .utf8)
        result.clientDataHash = "clientDataHash".data(using: .utf8)
        
        // Then
        XCTAssertThrowsError(try result.statement(), "Private key data invalid. Error should have been thrown but no Error was thrown") { error in
            XCTAssertEqual(error as? PublicKeyCredentialError, PublicKeyCredentialError.invalidPrivateKeyData)
        }
    }
    
    func testBasicAttestationStatementThrowInvalidPrivateKey() throws {
        // Given
        let invalidBase64PrivateKey = "QkhsNlIyeFFnMHUydGlUOXI2TlVsaVNKMXVDWjRuakhMSi9vQWNyZlIzZTlaL3RPTFA2cVlLdUJCQ0dCT1dkSnVBOWtnU0wyYWtRNW5KZ0w3RlFIc3NmS0RKUkFTcFkxMWhSNDdaNnFROUZ1Y3pDMnNiVFYrSitab3JoZW1EalcvZz09"
        var result = BasicAttestation(UUID(), base64PrivateKey: invalidBase64PrivateKey, base64Certificate: base64Certificate)
        result.authenticatorData = "authenticatorData".data(using: .utf8)
        result.clientDataHash = "clientDataHash".data(using: .utf8)
        
        // Then
        XCTAssertThrowsError(try result.statement(), "Unable to create private key. Error should have been thrown but no Error was thrown") { error in
            XCTAssertEqual(error as? PublicKeyCredentialError, PublicKeyCredentialError.unableToCreateKey)
        }
    }
    
    func testBasicAttestationStatementThrowCert() throws {
        // Given
        var result = BasicAttestation(UUID(), base64PrivateKey: base64PrivateKey, base64Certificate: base64Certificate  + "abc123")
        result.authenticatorData = "authenticatorData".data(using: .utf8)
        result.clientDataHash = "clientDataHash".data(using: .utf8)
        
        // Then
        XCTAssertThrowsError(try result.statement(), "Certificate data invalid. Error should have been thrown but no Error was thrown") { error in
                 XCTAssertEqual(error as? PublicKeyCredentialError, PublicKeyCredentialError.invalidCertificate)
        }
    }
    
    // MARK: NoneAttestation
    
    func testCreateNoneAttestation() throws {
        // Given
        let result = NoneAttestation()
        
        // Then
        XCTAssertNotNil(result)
    }
    
    func testNoneAttestationAaguid() throws {
        // Given
        let result = NoneAttestation()
        
        // Then
        XCTAssertEqual(result.aaguid, UUID().empty)
    }
    
    func testNoneAttestationStatement() throws {
        // Given
        let result = NoneAttestation()
        
        // When
        let value = result.statement()
        
        // Then
        XCTAssertEqual(value.count, 0)
    }
}
