//
// Copyright contributors to the IBM Verify DC SDK for iOS project
//

import XCTest
@testable import Core
@testable import DC

protocol CredentialTest {
    /// Tests the initiation of the `CredentialDescriptor` from JSON.
    func testInitiate() async throws
    
    /// Tests the initiation of the `CredentialDescriptor` from JSON with no proof attributes.
    func testWithAtrributes() async throws
 
    /// Tests the initiation of the `CredentialDescriptor` from JSON with no custom properties.
    func testWithNoProperties() async throws
    
    /// Tests the initiation of the `CredentialDescriptor` from JSON where the Base64 icon can not be converted to a `UIImage`.
    func testBadIconImage() async throws
    
    /// Tests the initiation of an array of `CredentialDescriptor` from JSON.
    func testInitiateArray() async throws
    
    /// Tests the initiation of an array of `CredentialDescriptor` from JSON where the structure is not present and throws exception.
    func testInitiateArrayFail() async throws
    
    /// Tests the initiation of an array of `CredentialDescriptor` from JSON where the structure is not present and throws exception.
    func testInitiateArrayInvalid() async throws
    
    /// Tests the initiation of an array of `CredentialDescriptor` from JSON where the the array is empty.
    func testInitiateArrayEmpty() async throws
    
    /// Tests the encoding of the `CredentialDescriptor` to JSON.
    func testEncoding() async throws
}

final class IndyCredentialTests: XCTestCase, CredentialTest {
    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testInitiate() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.credential-indy")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let result = try decoder.decode(IndyCredential.self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertEqual(result.id, "00e309ef-fcc5-44a4-86a7-aa4729b478da")
        XCTAssertEqual(result.role, CredentialRole.holder)
        XCTAssertEqual(result.state, CredentialState.stored)
        XCTAssertEqual(result.agentURL, URL(string: "https://diagency:9720/diagency/a2a/v1/messages/c83e9e40-93da-4db7-8104-7e4be64e1b98")!)
        XCTAssertEqual(result.agentName, "https://diagency:9720/diagency/a2a/v1/messages/c83e9e40-93da-4db7-8104-7e4be64e1b98")
        XCTAssertEqual(result.friendlyName!, "Australian Government")
        XCTAssertNotNil(result.icon)
        XCTAssertNotNil(result.jsonRepresentation)
        
        print(String(decoding: result.jsonRepresentation!, as: UTF8.self))
    }
    
    func testWithAtrributes() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.credential-no-attributes-indy")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let result = try decoder.decode(IndyCredential.self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertNotNil(result.jsonRepresentation)
    }
    
    func testWithNoProperties() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.credential-no-properties-indy")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let result = try decoder.decode(IndyCredential.self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertEqual(result.id, "ccab684d-910c-452b-acf4-89b0eb85e553")
        XCTAssertEqual(result.role, CredentialRole.holder)
        XCTAssertEqual(result.state, CredentialState.stored)
        XCTAssertNil(result.properties["name"])
        XCTAssertEqual(result.agentURL, URL(string: "https://diagency.default.svc.cluster.local:9720/diagency/a2a/v1/messages/ae32fa87-3296-498d-a5cd-c28becd28528")!)
        XCTAssertEqual(result.agentName, "DM_GovDMVIssuer")
        XCTAssertNil(result.friendlyName, "")
        XCTAssertTrue(Date.now.timeIntervalSince(result.offerTime) < 500)
        XCTAssertNil(result.icon)
    }
    
    func testBadIconImage() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.credential-bad-icon-indy")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let result = try decoder.decode(IndyCredential.self, from: data)
        
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
        XCTAssertEqual(result.count(where: { $0.type is IndyCredential }), 1)
    }
    
    func testInitiateArrayFail() async throws {
        // Given
        let data = """
            { "count": 1 }
        """.data(using: .utf8)!
        
        
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        XCTAssertThrowsError(try decoder.decode(type: [IndyCredential].self, from: data)) { error in
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
        XCTAssertThrowsError(try decoder.decode(type: [IndyCredential].self, from: data)) { error in
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
        let result = try decoder.decode(type: [IndyCredential].self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertEqual(result.count, 0)
    }
    
    func testEncoding() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.credential-indy")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .millisecondsSince1970
        encoder.outputFormatting = .prettyPrinted
        
        // Where
        let credential = try decoder.decode(IndyCredential.self, from: data)
        
        // Then
        XCTAssertNotNil(credential)
        
        // Then
        let result = try encoder.encode(credential)
        print(String(data: result, encoding: .utf8)!)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        let credential2 = try decoder.decode(IndyCredential.self, from: result)
        
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
