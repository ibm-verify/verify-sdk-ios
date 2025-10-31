//
// Copyright contributors to the IBM Verify FIDO2 SDK for iOS project
//

import XCTest
@testable import FIDO2

class PublicKeyCredentialProviderTests: XCTestCase {
    var error: Error?
    var expectation: XCTestExpectation?
    
    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testCreateThrow0() throws {
        // Given
        guard let url = Bundle.module.url(forResource: "ISVA.Attestation.Options", withExtension: "json", subdirectory: "Files") else {
            XCTFail("Missing file: ISVA.Attestation.Options.json")
            return
        }
        
        // When
        let data = try Data(contentsOf: url)
        let decoder = JSONDecoder()
        let options = try! decoder.decode(PublicKeyCredentialCreationOptions.self, from: data)
        
        XCTAssertNotNil(options)
        
        // Then
        self.expectation = expectation(description: "Testing request errors.")
        
        let provider = PublicKeyCredentialProvider()
        provider.delegate = self
        provider.createCredentialAttestationRequest(options: options)
    
        waitForExpectations(timeout: 1)
        
        let result = try XCTUnwrap(error)
        XCTAssertNotNil(result)
    }
}

extension PublicKeyCredentialProviderTests: PublicKeyCredentialDelegate {
    func publicKeyCredential(provider: PublicKeyCredentialProvider, didCompleteWithError error: Error) {
        self.error = error
        expectation?.fulfill()
        expectation = nil
    }
    
    func publicKeyCredential(provider: PublicKeyCredentialProvider, didCompleteWithAssertion result: PublicKeyCredential<AuthenticatorAssertionResponse>) {
        
        expectation?.fulfill()
        expectation = nil
    }
    
    func publicKeyCredential(provider: PublicKeyCredentialProvider, didCompleteWithAttestation result: PublicKeyCredential<AuthenticatorAttestationResponse>) {
        
        expectation?.fulfill()
        expectation = nil
    }
}
