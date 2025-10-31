//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import XCTest

class StringExtensionTests: XCTestCase {
    ///  Remove new lines and  null bytes from decoding.
    let whitespacesNewlinesAndNulls = CharacterSet.whitespacesAndNewlines.union(CharacterSet(["\0"]))

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    // Test empty string returning a nil.
    func testDecodeEmptyString() throws {
        // Given
        let value = ""
        
        // When
        let result = value.base32DecodedData()
            
        // Then
        XCTAssertNil(result)
    }
    
    // Test empty an array returning a nil.
    func testDecodeArray() throws {
        // Given
        let value = Array(repeating: UInt8(0), count: 10)
        
        // When
        let result = "AAAAAAAAAAAAAAAAA".base32DecodedData()
        
        // Then
        XCTAssertNotNil(result)
        XCTAssertEqual(value, [UInt8](result!))
    }
    
    // Test decoding against known RFC vectors.
    func testDecodeRFCVector1() throws {
        // Given
        let value = "f"
        
        // When
        let data = "MY======".base32DecodedData()!
        let result = String(decoding: data, as: UTF8.self).trimmingCharacters(in: whitespacesNewlinesAndNulls)

        // Then
        XCTAssertEqual(value, result)
    }
    
    // Test decoding against known RFC vectors.
    func testDecodeRFCVector2() throws {
        // Given
        let value = "fo"
        
        // When
        let data = "MZXQ====".base32DecodedData()!
        let result = String(decoding: data, as: UTF8.self).trimmingCharacters(in: whitespacesNewlinesAndNulls)
        
        // Then
        XCTAssertEqual(value, result)
    }
    
    // Test decoding against known RFC vectors.
    func testDecodeRFCVector3() throws {
        // Given
        let value = "foo"
        
        // When
        let data = "MZXW6===".base32DecodedData()!
        let result = String(decoding: data, as: UTF8.self).trimmingCharacters(in: whitespacesNewlinesAndNulls)
        
        // Then
        XCTAssertEqual(value, result)
    }
    
    // Test decoding against known RFC vectors.
    func testDecodeRFCVector4() throws {
        // Given
        let value = "foob"
        
        // When
        let data = "MZXW6YQ=".base32DecodedData()!
        let result = String(decoding: data, as: UTF8.self).trimmingCharacters(in: whitespacesNewlinesAndNulls)
        
        // Then
        XCTAssertEqual(value, result)
    }
    
    // Test decoding against known RFC vectors.
    func testDecodeRFCVector5() throws {
        // Given
        let value = "fooba"
        
        // When
        let data = "MZXW6YTB".base32DecodedData()!
        let result = String(decoding: data, as: UTF8.self).trimmingCharacters(in: whitespacesNewlinesAndNulls)
        
        // Then
        XCTAssertEqual(value, result)
    }
    
    // Test decoding against known RFC vectors.
    func testDecodeRFCVector6() throws {
        // Given
        let value = "foobar"
        
        // When
        let data = "MZXW6YTBOI======".base32DecodedData()!
        let result = String(decoding: data, as: UTF8.self).trimmingCharacters(in: whitespacesNewlinesAndNulls)
        
        // Then
        XCTAssertEqual(value, result)
    }
    
    // Test decoding against known RFC vectors.
    func testDecodeRFCVector7() throws {
        // Given
        let value = "Hello!"
        
        // When
        let data = "JBSWY3DPEE======".base32DecodedData()!
        let result = String(decoding: data, as: UTF8.self).trimmingCharacters(in: whitespacesNewlinesAndNulls)
        
        // Then
        XCTAssertEqual(value, result)
    }
    
    // Test converting a string to snake case.
    func testSnakeCase() throws {
        // Given
        let value = "testCase!"
        
        // When
        let result = value.toSnakeCase()
        
        
        // Then
        XCTAssertEqual("test_case!", result)
    }
}
