//
// Copyright contributors to the IBM Verify Authentication SDK for iOS project
//

import XCTest
import Core
@testable import Authentication
import CryptoKit


class DPoPHelperTests: XCTestCase {
    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    // Test generating a DPoP proof.
    func testGenarateProof() throws {
        // Given
        let key = RSA.Signing.PrivateKey()
        
        // Where
        let result = try DPoP.generateProof(key, uri: "https://sdk.verify.ibm.com/oauth2/token")
        print(result)
        
        // Then
        XCTAssertTrue(!result.isEmpty)
    }
    
    // Test generating a DPoP proof with access token.
    func testGenarateProofWithAccessToken() throws {
        // Given
        let key = RSA.Signing.PrivateKey()
        
        // Where
        let result = try DPoP.generateProof(key, uri: "http://localhost:8080/validate-token", method: .get, accessToken: "yFaQY5OKvYJ06b4p8hF3HJgrYjWKR_wIF2o-_RPz8hU.Kipym-vjiE9J80K4TVvKSoc7gbQnkUkgbziSku9-zC0Aeur8dYoaYLZlE0oaDL2ohh8k6qZ47hNQsM-0rB2nCw.M18xNjk4NzExMTk1XzQ0")
        print(result)
        
        // Then
        XCTAssertTrue(!result.isEmpty)
    }
    
    // Test generating a DPoP proof with a HTTP GET method.
    func testGenarateProofWithGetMethod() throws {
        // Given
        let key = RSA.Signing.PrivateKey()
        
        // Where
        let result = try DPoP.generateProof(key, uri: "https://example.com", method: .get)
        print(result)
        
        // Then
        XCTAssertTrue(!result.isEmpty)
    }
    
    // Test generating a DPoP proof with invalid url.
    func testGenarateProofInvalidURL() throws {
        // Given
        let key = RSA.Signing.PrivateKey()
        
        // Where, Them
        do {
            let _ = try DPoP.generateProof(key, uri: "")
        }
        catch let error {
            XCTAssertNotNil(error, error.localizedDescription)
        }
    }
    
    // Test generating a DPoP proof with invalid hash.
    func testGenarateProofInvalidHash() throws {
        // Given
        let key = RSA.Signing.PrivateKey()
        
        // Where, Them
        do {
            let _ = try DPoP.generateProof(key, hashAlgorithm: Insecure.SHA1(), uri: "https://example.com")
        }
        catch let error {
            XCTAssertNotNil(error, error.localizedDescription)
        }
    }
    
    // Test generating a DPoP proof with SHA384 hash.
    func testGenarateProofSHA384Hash() throws {
        // Given
        let key = RSA.Signing.PrivateKey()
        
        // Where, Them
        do {
            let _ = try DPoP.generateProof(key, hashAlgorithm: SHA384(), uri: "https://example.com")
        }
        catch let error {
            XCTAssertNotNil(error, error.localizedDescription)
        }
    }
    
    // Test generating a DPoP proof with SHA512 hash.
    func testGenarateProofSHA512Hash() throws {
        // Given
        let key = RSA.Signing.PrivateKey()
        
        // Where, Them
        do {
            let _ = try DPoP.generateProof(key, hashAlgorithm: SHA512(), uri: "https://example.com")
        }
        catch let error {
            XCTAssertNotNil(error, error.localizedDescription)
        }
    }
}
