//
// Copyright contributors to the IBM Verify Adaptive SDK for iOS project
//

import XCTest
@testable import Adaptive

class FactorTypeTests: XCTestCase {

    func testInitFromString() throws {
        // Where
        let value = "qr"
        
        // Then
        let factor = FactorType(rawValue: value)
        
        // Test
        XCTAssertTrue(factor == FactorType.qr, "Factor matches")
    }
}
