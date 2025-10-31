//
// Copyright contributors to the IBM Verify Authentication SDK for iOS project
//

import XCTest
@testable import Authentication

class PKCEHelperTests: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testGenarateCodeVerifier() throws {
        // Given, Where
        let result = PKCE.generateCodeVerifier()
        
        print("Code verifier: \(result)")
        
        // Then
        XCTAssertTrue(!result.isEmpty)
    }

    func testGenarateCodeChallenge() throws {
        // Given
        let value = PKCE.generateCodeVerifier()
        
        // Where
        guard let result = PKCE.generateCodeChallenge(from: value) else {
            XCTFail("Invalid result.")
            return
        }
        
        print("Code challenge: \(result)")
        
        // Then
        XCTAssertTrue(!result.isEmpty)
    }
}
