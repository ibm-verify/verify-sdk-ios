//
// Copyright contributors to the IBM Verify Core SDK for iOS project
//

import XCTest

class StringExtensionTests: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    /// Tests a string can not be url encoded.
    func testUrlNotEncoded() throws {
        // Given
        let value = String(bytes: [0xD8, 0x00] as [UInt8], encoding: .utf16BigEndian)
        
        // Where
        let result = value?.urlFormEncodedString
        
        // Then
        XCTAssertEqual(result, value)
    }
    
    /// Tests a string can be url encoded.
    func testUrlEncoded() throws {
        // Given"
        let value = "V_@H2tsWDT4PwKEAjb*C"
        
        // Where
        let result = value.urlFormEncodedString
        
        // Then
        XCTAssertEqual(result, "V_%40H2tsWDT4PwKEAjb%2AC")
    }
    
    /// Tests a string can be url encoded with padding.
    func testUrlEncodedPadding() throws {
        // Given"
        let value = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        
        // Where
        let result = value.base64UrlEncodedStringWithPadding
        
        // Then
        XCTAssertEqual(result, "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ==")
    }
}
