//
// Copyright contributors to the IBM Verify DC SDK for iOS project
//

import XCTest
import Authentication
@testable import DC

final class AgentTests: XCTestCase {
    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    /// Tests the initiation of the `Agent` from
    func testInitiate() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.agent.info")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let result = try decoder.decode(AgentInfo.self, from: data)
        
        // Then
        XCTAssertNotNil(result)
    }
}
