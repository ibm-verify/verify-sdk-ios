//
// Copyright contributors to the IBM Verify DC SDK for iOS project
//

import XCTest
@testable import Core
@testable import DC

final class InvitationTests: XCTestCase {
    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    /// Tests the initiation of the `InvitationInfo` from JSON.
    func testInitiate() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.invitation-connection")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let result = try decoder.decode(InvitationInfo.self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertEqual(result.id, "d7163ca5-58c4-4c5d-8e7f-1783f22f8afe")
    }
    
    /// Tests the initiation of the `InvitationInfo` from JSON with time stamps
    func testInitiateNoTimestamps() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.invitation-no-timestamps")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let result = try decoder.decode(InvitationInfo.self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        let value = try JSONEncoder().encode(result)
        XCTAssertNotNil(value)
    }
    
    /// Tests the initiation of the `InvitationInfo` from JSON.
    func testInitiateWithCredential() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.invitation-credential")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let result = try decoder.decode(InvitationInfo.self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertEqual(result.id, "5ad4dcd7-cb0a-41ba-ba20-f879ad53682a")
    }
    
    /// Tests the initiation of an array of `InvitationInfo` from JSON.
    func testInitiateArray() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.invitations")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let result = try decoder.decode(type: [InvitationInfo].self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertEqual(result.count, 1)
    }
    
    /// Tests the initiation of an array of `InvitationInfo` from JSON where the structure is not present and throws exception.
    func testInitiateArrayFail() async throws {
        // Given
        let data = """
            { "count": 1 }
        """.data(using: .utf8)!
        
        
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        XCTAssertThrowsError(try decoder.decode(type: [InvitationInfo].self, from: data)) { error in
            XCTAssertTrue(error is DecodingError)
        }
    }
    
    /// Tests the initiation of an array of `InvitationInfo` from JSON where the structure is not present and throws exception.
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
        XCTAssertThrowsError(try decoder.decode(type: [InvitationInfo].self, from: data)) { error in
            XCTAssertTrue(error is DecodingError)
        }
    }
    
    /// Tests the initiation of an array of `InvitationInfo` from JSON where the the array is empty.
    func testInitiateArrayEmpty() async throws {
        // Given
        let data = """
            { "count": 1, "items": [] }
        """.data(using: .utf8)!
        
        
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let result = try decoder.decode(type: [InvitationInfo].self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertEqual(result.count, 0)
    }
    
    /// Tests the encoding of the `InvitationInfo` to JSON.
    func testEncoding() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.invitation-connection")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .millisecondsSince1970
        encoder.outputFormatting = .prettyPrinted
        
        // Where
        let invitation = try decoder.decode(InvitationInfo.self, from: data)
        
        // Then
        XCTAssertNotNil(invitation)
        
        // Then
        let result = try encoder.encode(invitation)
        print(String(data: result, encoding: .utf8)!)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        let invitation2 = try decoder.decode(InvitationInfo.self, from: result)
        
        // Then
        XCTAssertEqual(invitation.id, invitation2.id)
        XCTAssertEqual(invitation.url, invitation2.url)
        XCTAssertEqual(invitation.recipientKey, invitation2.recipientKey)
        XCTAssertEqual(invitation.timestamps?.created, invitation2.timestamps?.created)
        XCTAssertEqual(invitation.timestamps?.updated, invitation2.timestamps?.updated)
    }
}
 
// MARK: Invitation Preview

final class InvitationPreviewTests: XCTestCase {
    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    /// Tests the initiation of the `InvitationPreviewInfo`  but fails on requests-attached not being present.
    func testInitiateFailOnAttach() async throws {
        // Given
        let data = """
        {
            "invitation": {
                "@id": "59754b7a-b79d-4055-8e48-f8c734801372",
                "@type": "https://didcomm.org/out-of-band/1.0/invitation",
                "label": "issuer_1",
                "short_url": "https://diagency:9720/diagency/a2a/v1/messages/3711d7cb-7e78-42a5-b5fe-393b39657079/invitation?id=59754b7a-b79d-4055-8e48-f8c734801372",
                "services": [
                    {
                        "id": "#inline",
                        "type": "did-communication",
                        "priority": 0,
                        "recipientKeys": [
                            "FWdbVFWr9rxdNxagXzH4h2Kgp8f9aUPQbQjDQmzcaY1W"
                        ],
                        "serviceEndpoint": "https://diagency:9720/diagency/a2a/v1/messages/3711d7cb-7e78-42a5-b5fe-393b39657079",
                        "routingKeys": []
                    },
                    "YGnU7s25JD3nGMdhLnBm5X"
                ],
                "handshake_protocols": [
                    "https://didcomm.org/didexchange/1.0",
                    "https://didcomm.org/connections/1.0"
                ],
                "requests~attach": [
                ]
            }
        }
        """.data(using: .utf8)!
        
        // Where
        do {
            let _ = try JSONDecoder().decode(InvitationPreviewInfo.self, from: data)
        }
        catch let error {
            // Then
            XCTAssertNotNil(error)
        }
    }
    
    /// Tests the initiation of the `InvitationPreviewInfo` from JSON but fails on offers-attached not being present.
    func testInitiateFailOnOffersl() async throws {
        // Given
        let data = """
        {
            "invitation": {
                "@id": "59754b7a-b79d-4055-8e48-f8c734801372",
                "@type": "https://didcomm.org/out-of-band/1.0/invitation",
                "label": "issuer_1",
                "short_url": "https://diagency:9720/diagency/a2a/v1/messages/3711d7cb-7e78-42a5-b5fe-393b39657079/invitation?id=59754b7a-b79d-4055-8e48-f8c734801372",
                "services": [
                    {
                        "id": "#inline",
                        "type": "did-communication",
                        "priority": 0,
                        "recipientKeys": [
                            "FWdbVFWr9rxdNxagXzH4h2Kgp8f9aUPQbQjDQmzcaY1W"
                        ],
                        "serviceEndpoint": "https://diagency:9720/diagency/a2a/v1/messages/3711d7cb-7e78-42a5-b5fe-393b39657079",
                        "routingKeys": []
                    },
                    "YGnU7s25JD3nGMdhLnBm5X"
                ],
                "handshake_protocols": [
                    "https://didcomm.org/didexchange/1.0",
                    "https://didcomm.org/connections/1.0"
                ],
                "requests~attach": [
                    {
                        "@id": "43e680f5-3bda-4ffa-94c8-6e9ff01d22f4",
                        "data": {
                            "json": {
                                "@type": "https://didcomm.org/issue-credential/2.0/offer-credential",
                                "@id": "43e680f5-3bda-4ffa-94c8-6e9ff01d22f4",
                                "comment": "",
                                "credential_preview": {
                                    "@type": "https://didcomm.org/issue-credential/1.0/credential-preview",
                                    "attributes": []
                                },
                                "formats": [
                                    {
                                        "attach_id": "43e680f5-3bda-4ffa-94c8-6e9ff01d22f4",
                                        "format": "aries/ld-proof-vc-detail@v1.0"
                                    }
                                ],
                                "offers~attach": [],
                            }
                        }
                    }
                ]
            }
        }
        """.data(using: .utf8)!
        
        // Where
        do {
            let _ = try JSONDecoder().decode(InvitationPreviewInfo.self, from: data)
        }
        catch let error {
            // Then
            XCTAssertNotNil(error)
        }
    }
    
    /// Tests the initiation of the `InvitationPreviewInfo`  from JSON but fails on getting the base64.
    func testInitiateFailOnBase64() async throws {
        // Given
        let data = """
        {
            "invitation": {
                "@id": "59754b7a-b79d-4055-8e48-f8c734801372",
                "@type": "https://didcomm.org/out-of-band/1.0/invitation",
                "label": "issuer_1",
                "short_url": "https://diagency:9720/diagency/a2a/v1/messages/3711d7cb-7e78-42a5-b5fe-393b39657079/invitation?id=59754b7a-b79d-4055-8e48-f8c734801372",
                "services": [
                    {
                        "id": "#inline",
                        "type": "did-communication",
                        "priority": 0,
                        "recipientKeys": [
                            "FWdbVFWr9rxdNxagXzH4h2Kgp8f9aUPQbQjDQmzcaY1W"
                        ],
                        "serviceEndpoint": "https://diagency:9720/diagency/a2a/v1/messages/3711d7cb-7e78-42a5-b5fe-393b39657079",
                        "routingKeys": []
                    },
                    "YGnU7s25JD3nGMdhLnBm5X"
                ],
                "handshake_protocols": [
                    "https://didcomm.org/didexchange/1.0",
                    "https://didcomm.org/connections/1.0"
                ],
                "requests~attach": [
                    {
                        "@id": "43e680f5-3bda-4ffa-94c8-6e9ff01d22f4",
                        "data": {
                            "json": {
                                "@type": "https://didcomm.org/issue-credential/2.0/offer-credential",
                                "@id": "43e680f5-3bda-4ffa-94c8-6e9ff01d22f4",
                                "comment": "",
                                "credential_preview": {
                                    "@type": "https://didcomm.org/issue-credential/1.0/credential-preview",
                                    "attributes": []
                                },
                                "formats": [
                                    {
                                        "attach_id": "43e680f5-3bda-4ffa-94c8-6e9ff01d22f4",
                                        "format": "aries/ld-proof-vc-detail@v1.0"
                                    }
                                ],
                                "offers~attach": [
                                    {
                                        "@id": "43e680f5-3bda-4ffa-94c8-6e9ff01d22f4",
                                        "mime-type": "application/ld+json",
                                        "data": {
                                            "base64": "abc"
                                        }
                                    }
                                ]
                            }
                        }
                    }
                ]
            }
        }
        """.data(using: .utf8)!
        
        // Where
        do {
            let _ = try JSONDecoder().decode(InvitationPreviewInfo.self, from: data)
        }
        catch let error {
            // Then
            XCTAssertNotNil(error)
        }
    }
}
