//
// Copyright contributors to the IBM Verify Core SDK for iOS project
//

import XCTest
@testable import Core

class ThreadExtensionTests: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testValidThreadNumber() throws {
        // Given
        let result = Thread.current.threadIdentifier
        
        print(Thread.current.description)
        
        // Then
        XCTAssertGreaterThan(result, 0)
    }
}
