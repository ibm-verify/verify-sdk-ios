//
// Copyright contributors to the IBM Verify Core SDK for iOS project
//

import XCTest
@testable import Core

class DataExtensionTests: XCTestCase {
    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testBase64UrlEncode() throws {
        // Given
        let value = "Lorem?ipsum"
        
        // Where
        guard let data = value.data(using: .utf8) else {
            XCTFail("Invalid data.")
            return
        }
        
        let result = data.base64UrlEncodedString()
        
        // Then
        XCTAssertEqual(result, "TG9yZW0/aXBzdW0=")
    }
}
