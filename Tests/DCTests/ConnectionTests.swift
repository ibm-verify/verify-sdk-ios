//
// Copyright contributors to the IBM Verify DC SDK for iOS project
//

import XCTest
@testable import Core
@testable import DC

final class ConnectionTests: XCTestCase {
    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    /// Tests the initiation of the `ConnectionInfo` from JSON.
    func testInitiate() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.connection")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let result = try decoder.decode(ConnectionInfo.self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertEqual(result.name, "GovDMVIssuer")
        XCTAssertNotNil(result.icon)
    }
    
    /// Tests the initiation of the `ConnectionInfo` where the icon cannot be created from the `InvitationInfo`. properties.
    func testBadIconImage() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.connection-bad-icon")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let result = try decoder.decode(ConnectionInfo.self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertNil(result.icon)
    }
    
    /// Tests the initiation of the `ConnectionInfo` where no icon is referenced in the `InvitationInfo`. properties.
    func testNoIcon() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.connection-no-icon")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let result = try decoder.decode(ConnectionInfo.self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertNil(result.icon)
    }
    
    /// Tests the initiation of the `ConnectionInfo` where no `InvitationInfo` is referenced.
    func testNoInvitationIcon() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.connection-no-invitation")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let result = try decoder.decode(ConnectionInfo.self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertNil(result.icon)
    }
    
    /// Tests the initiation of an array of `ConnectionInfo` from JSON.
    func testInitiateArray() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.conections")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        
        // Where
        let result = try decoder.decode(type: [ConnectionInfo].self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertEqual(result.count, 1)
    }
    
    /// Tests the initiation of an array of `ConnectionInfo` from JSON where the structure is not present and throws exception.
    func testInitiateArrayFail() async throws {
        // Given
        let data = """
            { "count": 1 }
        """.data(using: .utf8)!
        
        
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        XCTAssertThrowsError(try decoder.decode(type: [ConnectionInfo].self, from: data)) { error in
            XCTAssertTrue(error is DecodingError)
        }
    }
    
    /// Tests the initiation of an array of `ConnectionInfo` from JSON where the structure is not present and throws exception.
    func testInitiateArrayInvalid() async throws {
        // Given
        let data = """
            {
                "count": 1,
                "items": [{
                    "name": "user"
                }]
        }
        """.data(using: .utf8)!
        
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        XCTAssertThrowsError(try decoder.decode(type: [ConnectionInfo].self, from: data)) { error in
            XCTAssertTrue(error is DecodingError)
        }
    }
    
    /// Tests the initiation of an array of `ConnectionInfo` from JSON where the the arrat is empty.
    func testInitiateArrayEmpty() async throws {
        // Given
        let data = """
            { "count": 1, "items": [] }
        """.data(using: .utf8)!
        
        
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let result = try decoder.decode(type: [ConnectionInfo].self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertEqual(result.count, 0)
    }
    
    
    /// Tests the initiation of the `ConnectionAgentInfo` from JSON.
    func testConnectionAgentInfoLocal() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.connection")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let connection = try decoder.decode(ConnectionInfo.self, from: data)
        
        // Then
        XCTAssertNotNil(connection)
        
        // Then
        let connectionAgent = connection.local
        
        // Then
        XCTAssertNotNil(connectionAgent)
        
        // Then
        XCTAssertEqual(connectionAgent.name, "user_1")
    }
    
    /// Tests the initiation of the `ConnectionAgentInfo` from JSON.
    func testConnectionAgentInfoRemote() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.connection")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let connection = try decoder.decode(ConnectionInfo.self, from: data)
        
        // Then
        XCTAssertNotNil(connection)
        
        // Then
        let connectionAgent = connection.remote
        
        // Then
        XCTAssertNotNil(connectionAgent)
        
        // Then
        XCTAssertEqual(connectionAgent.name, "GovDMVIssuer")
    }

    
    /// Tests the encoding of the `ConnectionInfo` to JSON.
    func testEncoding() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.connection")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .millisecondsSince1970
        encoder.outputFormatting = .prettyPrinted
        
        // Where
        let connection = try decoder.decode(ConnectionInfo.self, from: data)
        
        // Then
        XCTAssertNotNil(connection)
        
        // Then
        let result = try encoder.encode(connection)
        print(String(data: result, encoding: .utf8)!)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        let connection2 = try decoder.decode(ConnectionInfo.self, from: result)
        
        // Then
        XCTAssertEqual(connection.id, connection2.id)
        XCTAssertEqual(connection.name, connection2.name)
        XCTAssertEqual(connection.role, connection2.role)
        XCTAssertEqual(connection.state, connection2.state)
        
        // Then
        XCTAssertNotNil(connection.remote.public)
        XCTAssertNotNil(connection2.remote.public)
            
        // Then
        XCTAssertEqual(connection.local.pairwise.did, connection2.local.pairwise.did)
        XCTAssertEqual(connection.local.pairwise.verkey, connection2.local.pairwise.verkey)
    }
}
