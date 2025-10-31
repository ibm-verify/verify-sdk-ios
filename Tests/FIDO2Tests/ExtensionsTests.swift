//
// Copyright contributors to the IBM Verify FIDO2 SDK for iOS project
//

import XCTest
import CryptoKit
@testable import FIDO2

class ExtensionsTests: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    // MARK: UUID
    
    func testUUIDEmpty() throws {
        // Given
        let result = UUID().empty
        
        // Then
        XCTAssertEqual(result.uuidString, "00000000-0000-0000-0000-000000000000")
    }

    func testUUIDArray() throws {
        // Given
        let result = UUID().empty
        let expected: [UInt8] = [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        
        // Then
        XCTAssertEqual(result.uuidArray, expected)
    }
    
    // MARK: Data
    
    func testDataBase64URLEncoding() throws {
        // Given
        // https://mydomain.com?search=hello_world+today
        let expected = "aHR0cHM6Ly9teWRvbWFpbi5jb20_c2VhcmNoPWhlbGxvX3dvcmxkK3RvZGF5"
        
        let encoded = "aHR0cHM6Ly9teWRvbWFpbi5jb20/c2VhcmNoPWhlbGxvX3dvcmxkK3RvZGF5"
        
        // Where
        let data = Data(base64Encoded: encoded)
        let result = data?.base64URLEncodedString()
        
        // Then
        XCTAssertEqual(result, expected)
    }
    
    // MARK: String
    
    func testSrtringBase64URLEncoding() throws {
        // Given
        // https://mydomain.com?search=hello_world+today
        let expected = "aHR0cHM6Ly9teWRvbWFpbi5jb20_c2VhcmNoPWhlbGxvX3dvcmxkK3RvZGF5"
        
        let encoded = "aHR0cHM6Ly9teWRvbWFpbi5jb20/c2VhcmNoPWhlbGxvX3dvcmxkK3RvZGF5"
        
        // Where
        let data = Data(base64Encoded: encoded)
        let result = data?.base64URLEncodedString()
        
        // Then
        XCTAssertEqual(result, expected)
    }
    
    // MARK: CryptoKit
    
    func testCreateSecKeyConvertibleRawRepresentation() throws {
        // Given
        let value = SymmetricKey(size: SymmetricKeySize.bits256)
        let result = value.rawRepresentation
        
        // Then
        XCTAssertNotNil(result)
    }
    
    func testGetSecKeyConvertibleDataepresentation() throws {
        // Given
        let value = SymmetricKey(size: SymmetricKeySize.bits256)
        
        // Then
        XCTAssertNotNil(value.dataRepresentation)
    }
    
    func testGetSecKeyConvertibleRawRepresentation() throws {
        // Given
        let value = SymmetricKey(size: SymmetricKeySize.bits256)
        
        // Then
        XCTAssertNotNil(value.rawRepresentation)
    }
    
    func testCreateSecKeyConvertibleInit() throws {
        // Given
        let value = SymmetricKey(size: SymmetricKeySize.bits256)
        let data = value.rawRepresentation
        
        // When
        let result = try SymmetricKey(rawRepresentation: data)
        
        // Then
        XCTAssertNotNil(result)
    }
}
