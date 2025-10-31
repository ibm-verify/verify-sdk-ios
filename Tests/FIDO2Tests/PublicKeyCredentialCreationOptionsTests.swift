//
// Copyright contributors to the IBM Verify FIDO2 SDK for iOS project
//

import XCTest
@testable import FIDO2

//extension Bundle {
//    /// The bundle associated with the current Swift module.
//    static let module: Bundle = Bundle(for: type(of: self))
//}

class PublicKeyCredentialCreationOptionsTests: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testCreateFromISVAFile() throws {
        // Given
        guard let url = Bundle.module.url(forResource: "ISVA.Attestation.Options", withExtension: "json", subdirectory: "Files") else {
            XCTFail("Missing file: ISVA.Attestation.Options.json")
            return
        }
        
        do {
            // When
            let data = try Data(contentsOf: url)
            let decoder = JSONDecoder()
            let result = try decoder.decode(PublicKeyCredentialCreationOptions.self, from: data)

            // Then
            XCTAssertNotNil(result)
        }
        catch let error {
            print("Unknown error: \(error.localizedDescription)")
            XCTFail()
        }
    }
    
    func testCreateFromISVFile() throws {
        // Given
        guard let url = Bundle.module.url(forResource: "ISV.Attestation.Options", withExtension: "json", subdirectory: "Files") else {
            XCTFail("Missing file: ISVA.Attestation.Options.json")
            return
        }
        
        do {
            // When
            let data = try Data(contentsOf: url)
            let decoder = JSONDecoder()
            let result = try decoder.decode(PublicKeyCredentialCreationOptions.self, from: data)
            
            // Then
            XCTAssertNotNil(result)
        }
        catch let error {
            print("Unknown error: \(error.localizedDescription)")
            XCTFail()
        }
    }
    
    func testCreateFromRpUserSelection() throws {
        // Given
        let rpEntity = PublicKeyCredentialRpEntity(id: "mydomain.com", name: "mydomain.com", icon: nil)
        let userEntity = PublicKeyCredentialUserEntity(id: "JohnD", displayName: "John Doe", name: "John Doe")
        let selectionCriteria = AuthenticatorSelectionCriteria()
        
        // When
        let result = PublicKeyCredentialCreationOptions(rp: rpEntity, user: userEntity, challenge: UUID().uuidString, authenticatorSelection: selectionCriteria)
        
        // Then
        XCTAssertNotNil(result)
    }
    
    func testCreateFromRpUserSelectionMinEx() throws {
        // Given
        let rpEntity = PublicKeyCredentialRpEntity(id: "mydomain.com", name: "mydomain.com", icon: nil)
        let userEntity = PublicKeyCredentialUserEntity(id: "JohnD", displayName: "John Doe", name: "John Doe")
        let selectionCriteria = AuthenticatorSelectionCriteria()
        
        // When
        let result = PublicKeyCredentialCreationOptions(rp: rpEntity, user: userEntity, challenge: UUID().uuidString, timeout: 10000, excludeCredentials: [], authenticatorSelection: selectionCriteria, attestation: .none, pubKeyCredParams: [])
        
        // Then
        XCTAssertNotNil(result)
    }
    
    func testCreateFromRpUserSelectionAllEx() throws {
        // Given
        let rpEntity = PublicKeyCredentialRpEntity(id: "mydomain.com", name: "mydomain.com", icon: nil)
        let userEntity = PublicKeyCredentialUserEntity(id: "JohnD", displayName: "John Doe", name: "John Doe")
        let selectionCriteria = AuthenticatorSelectionCriteria()
        let excludeCredentials = [PublicKeyCredentialDescriptor(id: UUID().uuidString)]
        let publicKeyCredParams = [PublicKeyCredentialParameters(alg: COSEAlgorithmIdentifier.es256)]
        
        // When
        let result = PublicKeyCredentialCreationOptions(rp: rpEntity, user: userEntity, challenge: UUID().uuidString, timeout: 10000, excludeCredentials: excludeCredentials, authenticatorSelection: selectionCriteria, attestation: .none, pubKeyCredParams: publicKeyCredParams)
        
        // Then
        XCTAssertNotNil(result)
    }
}
