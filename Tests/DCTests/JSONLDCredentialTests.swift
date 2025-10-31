//
// Copyright contributors to the IBM Verify DC SDK for iOS project
//

import XCTest
@testable import Core
@testable import DC

final class JSONLDCredentialTests: XCTestCase, CredentialTest {
    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testInitiate() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.credential-jsonld")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let result = try decoder.decode(JSONLDCredential.self, from: data)
       
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertEqual(result.id, "740144cc-91be-4cab-871b-25459862296d")
        XCTAssertEqual(result.role, CredentialRole.holder)
        XCTAssertEqual(result.state, CredentialState.stored)
        XCTAssertEqual(result.properties["name"], "Australian Government")
        XCTAssertEqual(result.agentURL, URL(string: "https://diagency:9720/diagency/a2a/v1/messages/2ff54280-6172-462f-ba4a-b0e2be704670")!)
        XCTAssertEqual(result.agentName, "https://diagency:9720/diagency/a2a/v1/messages/2ff54280-6172-462f-ba4a-b0e2be704670")
        XCTAssertEqual(result.friendlyName, "Australian Government")
        XCTAssertNotNil(result.icon)
        XCTAssertNotNil(result.jsonRepresentation)
    }
    
    func testWithAtrributes() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.credential-no-attributes-jsonld")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let result = try decoder.decode(JSONLDCredential.self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertNotNil(result.jsonRepresentation)
    }
    
    func testWithNoProperties() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.credential-no-properties-jsonld")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let result = try decoder.decode(JSONLDCredential.self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertTrue(result.properties.isEmpty)
        XCTAssertNil(result.properties["name"])
        XCTAssertEqual(result.agentURL, URL(string: "https://diagency:9720/diagency/a2a/v1/messages/ab44653d-101a-4712-8a1e-40fc58816b06")!)
        XCTAssertEqual(result.agentName, "issuer-1729219549")
        XCTAssertNil(result.friendlyName)
        XCTAssertTrue(Date.now.timeIntervalSince(result.offerTime) < 500)
        XCTAssertNil(result.icon)
    }
    
    func testBadIconImage() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.credential-bad-icon-indy")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let result = try decoder.decode(JSONLDCredential.self, from: data)
        
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
        XCTAssertTrue(result.count > 0)
        XCTAssertNotNil(result[0].id)
        XCTAssertTrue(result[0].documentTypes.count > 0)
        
        // Then
        XCTAssertEqual(result.count(where: { $0.type is JSONLDCredential }), 1)
    }
    
    func testInitiateArrayFail() async throws {
        // Given
        let data = """
            { "count": 1 }
        """.data(using: .utf8)!
        
        
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        XCTAssertThrowsError(try decoder.decode(type: [JSONLDCredential].self, from: data)) { error in
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
        XCTAssertThrowsError(try decoder.decode(type: [JSONLDCredential].self, from: data)) { error in
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
        let result = try decoder.decode(type: [JSONLDCredential].self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertEqual(result.count, 0)
    }
    
    func testEncoding() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.credential-jsonld")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .millisecondsSince1970
        encoder.outputFormatting = .prettyPrinted
        
        // Where
        let credential = try decoder.decode(JSONLDCredential.self, from: data)
        
        // Then
        XCTAssertNotNil(credential)
        
        // Then
        let result = try encoder.encode(credential)
        print(String(data: result, encoding: .utf8)!)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        let credential2 = try decoder.decode(JSONLDCredential.self, from: result)
        
        // Then
        XCTAssertEqual(credential.id, credential2.id)
        XCTAssertEqual(credential.role, credential2.role)
        XCTAssertEqual(credential.state, credential2.state)
        XCTAssertEqual(credential.properties["name"], credential2.properties["name"])
        XCTAssertEqual(credential.agentURL, credential2.agentURL)
        XCTAssertEqual(credential.agentName, credential2.agentName)
        XCTAssertEqual(credential.jsonRepresentation?.count, credential2.jsonRepresentation?.count)
    }
}
