//
// Copyright contributors to the IBM Verify DC SDK for iOS project
//

import XCTest
@testable import Core
@testable import DC

final class MDocCredentialTests: XCTestCase, CredentialTest {
    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testInitiate() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.credential-mdoc")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let result = try decoder.decode(MDocCredential.self, from: data)
       
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertEqual(result.id, "6da40c46-c12e-4d7d-a865-415cb239c62f")
        XCTAssertEqual(result.role, CredentialRole.holder)
        XCTAssertEqual(result.state, CredentialState.stored)
        XCTAssertEqual(result.properties["name"], "Australian Government")
        XCTAssertEqual(result.agentURL, URL(string: "https://diagency:9720/diagency/a2a/v1/messages/eec19c85-d8e7-4694-8520-19762b0e76f7")!)
        XCTAssertEqual(result.agentName,
                       "https://diagency:9720/diagency/a2a/v1/messages/eec19c85-d8e7-4694-8520-19762b0e76f7")
        XCTAssertEqual(result.friendlyName, "Australian Government")
        XCTAssertNotNil(result.icon)
    }
    
    func testWithAtrributes() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.credential-no-attributes-mdoc")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let result = try decoder.decode(MDocCredential.self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertNotNil(result.jsonRepresentation)
    }
    
   func testWithNoProperties() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.credential-no-properties-mdoc")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let result = try decoder.decode(MDocCredential.self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertTrue(result.properties.isEmpty)
        XCTAssertNil(result.properties["name"])
        XCTAssertEqual(result.agentURL, URL(string: "https://diagency:9720/diagency/a2a/v1/messages/2ff54280-6172-462f-ba4a-b0e2be704670")!)
        XCTAssertEqual(result.agentName, "https://diagency:9720/diagency/a2a/v1/messages/2ff54280-6172-462f-ba4a-b0e2be704670")
        XCTAssertNil(result.friendlyName)
        XCTAssertTrue(Date.now.timeIntervalSince(result.offerTime) < 500)
        XCTAssertNil(result.icon)
    }
    
    func testBadIconImage() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.credentail-bad-icon-mdoc")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let result = try decoder.decode(MDocCredential.self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertNil(result.icon)
    }
    
    func testInitiateArray() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.credentials-mixed")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let result = try decoder.decode(type: [Credential].self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertEqual(result.count(where: { $0.type is MDocCredential }), 1)
    }
    
    func testInitiateArrayFail() async throws {
        // Given
        let data = """
            { "count": 1 }
        """.data(using: .utf8)!
        
        
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        XCTAssertThrowsError(try decoder.decode(type: [MDocCredential].self, from: data)) { error in
            XCTAssertTrue(error is DecodingError)
        }
    }
    
    func testInitiateArrayInvalid() async throws {
        // Given
        let data = """
            {
                "count": 1,
                "items": [{
                    "role": "holder"
                }]
        }
        """.data(using: .utf8)!
        
        
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        XCTAssertThrowsError(try decoder.decode(type: [MDocCredential].self, from: data)) { error in
            XCTAssertTrue(error is DecodingError)
        }
    }
    
    func testInitiateArrayEmpty() async throws {
        // Given
        let data = """
            { "count": 1, "items": [] }
        """.data(using: .utf8)!
        
        
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let result = try decoder.decode(type: [MDocCredential].self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertEqual(result.count, 0)
    }
    
    func testEncoding() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.credential-mdoc")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .millisecondsSince1970
        encoder.outputFormatting = .prettyPrinted
        
        // Where
        let credential = try decoder.decode(MDocCredential.self, from: data)
        
        // Then
        XCTAssertNotNil(credential)
        
        // Then
        let result = try encoder.encode(credential)
        print(String(data: result, encoding: .utf8)!)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        let credential2 = try decoder.decode(MDocCredential.self, from: result)
        
        // Then
        XCTAssertEqual(credential.id, credential2.id)
        XCTAssertEqual(credential.role, credential2.role)
        XCTAssertEqual(credential.state, credential2.state)
        XCTAssertEqual(credential.properties["name"], credential2.properties["name"])
        XCTAssertEqual(credential.agentURL, credential2.agentURL)
        XCTAssertEqual(credential.agentName, credential2.agentName)
    }
}
