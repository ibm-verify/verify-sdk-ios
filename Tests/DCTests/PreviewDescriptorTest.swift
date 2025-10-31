//
//  AgentTests 2.swift
//  IBM Verify
//
//  Created by Craig Pearson on 25/10/2024.
//


//
// Copyright contributors to the IBM Verify DC SDK for iOS project
//

import XCTest
@testable import DC

// MARK: Credential Previews

final class CredentialPreviewTests: XCTestCase {
    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    // Tests the initiation of the `CredentialPreviewInfo` from Indy credential.
    func testInitiateWithIndy() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.invitation-processor-cred-offer-indy")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let preview = try decoder.decode(InvitationPreviewInfo.self, from: data)
        
        // Then
        XCTAssertNotNil(preview)
        
        // Then
        let credentialPreview = CredentialPreviewInfo(using: preview)
        XCTAssertNotNil(credentialPreview)
        XCTAssertTrue(credentialPreview.documentTypes.count > 0)
    }
    
    /// Tests the initiation of the `CredentialPreviewInfo` from MDOC credential.
    func testInitiateWithMDoc() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.invitation-processor-cred-offer-mdoc")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let preview = try decoder.decode(InvitationPreviewInfo.self, from: data)
        
        // Then
        XCTAssertNotNil(preview)
        
        // Then
        let credentialPreview = CredentialPreviewInfo(using: preview)
        XCTAssertNotNil(credentialPreview)
        XCTAssertTrue(credentialPreview.documentTypes.count > 0)
    }
    
    /// Tests the initiation of the `CredentialPreviewInfo` from JSON-LD credential.
    func testInitiateWithJSONLD() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.invitation-processor-cred-offer-jsonld")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let preview = try decoder.decode(InvitationPreviewInfo.self, from: data)
        
        // Then
        XCTAssertNotNil(preview)
        
        // Then
        let credentialPreview = CredentialPreviewInfo(using: preview)
        XCTAssertNotNil(credentialPreview)
        XCTAssertTrue(credentialPreview.documentTypes.count > 0)
    }
    
    /// Tests the initiation of the `CredentialPreviewInfo`  via the property init.
    func testInitiateCredentialPreviewInfo() async throws {
        // Given
        let preview = CredentialPreviewInfo(id: "test", url: URL(string: "https://test.credential.com")!, label: "label", comment: "Comment", jsonRepresentation: nil, documentTypes: ["VerifiableCredential"])
        
        // Where, Then
        XCTAssertNotNil(preview)
    }
    
    /// Tests the initiation of the `CredentialPreviewInfo`  with default formats and unknown document type.
    func testInitiateNoFormats() async throws {
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
                                        "format": "unknown"
                                    }
                                ],
                                "offers~attach": [
                                    {
                                        "@id": "43e680f5-3bda-4ffa-94c8-6e9ff01d22f4",
                                        "mime-type": "application/ld+json",
                                        "data": {
                                            "base64": "eyJjcmVkZW50aWFsIjp7ImlkIjoiaHR0cHM6Ly9pc3N1ZXIudmVyaWZ5LmlibS5jb20vY3JlZGVudGlhbHMvODM2Mjc0NjUiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVW5pdmVyc2l0eURlZ3JlZUNyZWRlbnRpYWwiXSwiaWRlbnRpZmllciI6IjgzNjI3NDY1IiwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6ZXhhbXBsZTpiMzRjYTZjZDM3YmJmMjMiLCJkZWdyZWUiOiJNYXN0ZXIgb2YgVkMiLCJmYW1pbHlOYW1lIjoiQnJldG9uIiwiZ2l2ZW5OYW1lIjoiSmVzc2ljYSJ9LCJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxIiwiaHR0cHM6Ly93M2lkLm9yZy9jaXRpemVuc2hpcC92MSIsImh0dHBzOi8vdzNpZC5vcmcvc2VjdXJpdHkvc3VpdGVzL2VkMjU1MTktMjAyMC92MSJdfSwib3B0aW9ucyI6eyJwcm9vZlB1cnBvc2UiOiJhc3NlcnRpb25NZXRob2QiLCJwcm9vZlR5cGUiOiJFZDI1NTE5VmVyaWZpY2F0aW9uS2V5MjAyMCJ9fQ=="
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
        let preview = try JSONDecoder().decode(InvitationPreviewInfo.self, from: data)
        
        // Then
        XCTAssertNotNil(preview)
        
        // Then
        let credentialPreview = CredentialPreviewInfo(using: preview)
        
        // Then
        XCTAssertNotNil(credentialPreview)
        XCTAssertEqual(credentialPreview.documentTypes.count, 0)
    }
}

// MARK: Verification Preview

final class VerificationPreviewTests: XCTestCase {
    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    // Tests the initiation of the `VerificationPreviewInfo` from mDoc.
    func testInitiateWithMdoc() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.invitation-processor-verification-mdoc")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let preview = try decoder.decode(InvitationPreviewInfo.self, from: data)
        
        // Then
        XCTAssertNotNil(preview)
        
        // Then
        let verificationPreview = VerificationPreviewInfo(using: preview)
        XCTAssertNotNil(verificationPreview)
        XCTAssertTrue(verificationPreview.documentTypes.count > 0)
    }
    
    // Tests the initiation of the `VerificationPreviewInfo` from Indy.
    func testInitiateWithIndy() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.invitation-processor-verification-indy")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let preview = try decoder.decode(InvitationPreviewInfo.self, from: data)
        
        // Then
        XCTAssertNotNil(preview)
        
        // Then
        let verificationPreview = VerificationPreviewInfo(using: preview)
        XCTAssertNotNil(verificationPreview)
        XCTAssertTrue(verificationPreview.documentTypes.count > 0)
    }
    
    // Tests the initiation of the `VerificationPreviewInfo` from Indy with the "cred-def-id" at the base64 root.
    func testInitiateWithIndyRootCredDef() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.invitation-processor-verification-base64-a-indy")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let preview = try decoder.decode(InvitationPreviewInfo.self, from: data)
        
        // Then
        XCTAssertNotNil(preview)
        
        // Then
        let verificationPreview = VerificationPreviewInfo(using: preview)
        XCTAssertNotNil(verificationPreview)
        XCTAssertTrue(verificationPreview.documentTypes.count > 0)
    }
    
    // Tests the initiation of the `VerificationPreviewInfo` from Indy with no "cred-def-id" in the base64.
    func testInitiateWithIndyNoCredDef() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.invitation-processor-verification-base64-b-indy")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let preview = try decoder.decode(InvitationPreviewInfo.self, from: data)
        
        // Then
        XCTAssertNotNil(preview)
        
        // Then
        let verificationPreview = VerificationPreviewInfo(using: preview)
        XCTAssertNotNil(verificationPreview)
        XCTAssertTrue(verificationPreview.documentTypes.count == 0)
    }
    
    // Tests the initiation of the `VerificationPreviewInfo` from JSON-LD.
    func testInitiateWithJSONLD() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.invitation-processor-verification-jsonld")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let preview = try decoder.decode(InvitationPreviewInfo.self, from: data)
        
        // Then
        XCTAssertNotNil(preview)
        
        // Then
        let verificationPreview = VerificationPreviewInfo(using: preview)
        XCTAssertNotNil(verificationPreview)
        XCTAssertTrue(verificationPreview.documentTypes.count > 0)
    }
}
