//
// Copyright contributors to the IBM Verify DC SDK for iOS project
//

import XCTest
@testable import Core
@testable import DC

final class VerificationInfoTests: XCTestCase {
    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    // MARK: Verifier
    
    /// Tests the initiation of the `VerificationInfo` from JSON for a verifier role.
    func testInitiateVerificationInfoForVerifierRequest() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "verifier.outbound-proof-request")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        
        // Where
        let result = try decoder.decode(VerificationInfo.self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertEqual(result.id, "5417b4d6-db87-4d66-88a9-a4346ed8103c")
        XCTAssertEqual(result.role,  VerificationRole.verifier)
        XCTAssertEqual(result.state, VerificationState.outboundProofRequest)
        XCTAssertEqual(result.verifierDID, "PREKx7ejSbfvDraDEu7JxE")
        XCTAssertEqual(result.proofSchemaId, "Citizen-didweb-1726180337209-verifier:0.0.1")
        XCTAssertNotNil(result.proofRequest)
        XCTAssertNil(result.info)
    }
    
    // MARK: Prover
    
    /// Tests the initiation of the `VerificationInfo` from JSON for a prover role.
    func testInitiateVerificationInfoForProver() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "prover.inbound-proof-request")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let result = try decoder.decode(VerificationInfo.self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertEqual(result.id, "5417b4d6-db87-4d66-88a9-a4346ed8103c")
        XCTAssertEqual(result.role,  VerificationRole.prover)
        XCTAssertEqual(result.state, VerificationState.inboundProofRequest)
        XCTAssertEqual(result.verifierDID, "PREKx7ejSbfvDraDEu7JxE")
        XCTAssertNil(result.proofSchemaId)
        XCTAssertNotNil(result.proofRequest)
        XCTAssertNil(result.info)
    }
    
    /// Tests the initiation of the `VerificationInfo` from JSON for a prover role.
    func testInitiateVerificationInfoProverGenerated() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "prover.proof-generated")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        
        // Where
        let result = try decoder.decode(VerificationInfo.self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertEqual(result.id, "5417b4d6-db87-4d66-88a9-a4346ed8103c")
        XCTAssertEqual(result.role,  VerificationRole.prover)
        XCTAssertEqual(result.state, VerificationState.proofGenerated)
        XCTAssertEqual(result.verifierDID, "PREKx7ejSbfvDraDEu7JxE")
        XCTAssertNil(result.proofSchemaId)
        XCTAssertNotNil(result.proofRequest)
        XCTAssertNotNil(result.info)
    }
    
    /// Tests the initiation of the `VerificationInfo` from JSON for a prover role.
    func testInitiateVerificationInfoProverPassJSONLD() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "prover.verification-passed-jsonld")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        
        // Where
        let result = try decoder.decode(VerificationInfo.self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertEqual(result.id, "4a8d2622-1e08-40ae-a6ef-a0912d3f7aa1")
        XCTAssertEqual(result.role,  VerificationRole.prover)
        XCTAssertEqual(result.state, VerificationState.passed)
        XCTAssertEqual(result.verifierDID, "9Yr4Nz1g6eAJMhpn3hivFxSK53v4zYgUxaqvons3gpY4")
        XCTAssertNil(result.proofSchemaId)
        XCTAssertNotNil(result.proofRequest)
        XCTAssertNotNil(result.info)
    }
    
    /// Tests the initiation of the `VerificationInfo` from Indy for a prover role.
    func testInitiateVerificationInfoProverPassIndy() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "prover.verification-passed-indy")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        
        // Where
        let result = try decoder.decode(VerificationInfo.self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertEqual(result.id, "21bffaa7-3c5d-43da-bd02-dda42551f9a0")
        XCTAssertEqual(result.role,  VerificationRole.prover)
        XCTAssertEqual(result.state, VerificationState.passed)
        XCTAssertEqual(result.verifierDID, "734joPStctNUbPeTV5LPbJRH1D3bMcTQXY6FEDTPjn2y")
        XCTAssertNil(result.proofSchemaId)
        XCTAssertNotNil(result.proofRequest)
        XCTAssertNotNil(result.info)
    }
    
    /// Tests the initiation of the `VerificationInfo` from JSON for a prover role for mDoc credential.
    func testInitiateVerificationInfoProverPassMDoc() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "prover.verification-passed-mdoc")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        
        // Where
        let result = try decoder.decode(VerificationInfo.self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertEqual(result.id, "e10f8703-a13f-4ded-ae51-d63fca398886")
        XCTAssertEqual(result.role,  VerificationRole.prover)
        XCTAssertEqual(result.state, VerificationState.passed)
        XCTAssertEqual(result.verifierDID, "9BwmP9f4UsQ1c48rADvkXT17DY1JvJWvQV6GeuQSQDQ3")
        XCTAssertNil(result.proofSchemaId)
        XCTAssertNotNil(result.proofRequest)
        XCTAssertNotNil(result.info)
    }
    
    /// Tests the initiation of the `VerificationInfo` from JSON for a prover role.
    func testInitiateVerificationInfoProverDeleted() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "prover.proof-deleted")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        
        // Where
        let result = try decoder.decode(VerificationInfo.self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertEqual(result.id, "0467a4ae-4162-4e52-bb47-b6fc73624c72")
        XCTAssertEqual(result.role,  VerificationRole.prover)
        XCTAssertEqual(result.state, VerificationState.deleted)
        XCTAssertEqual(result.verifierDID, "539fAvLFY7QCDFaBmBdbsZ")
        XCTAssertNotNil(result.proofSchemaId)
        
        // Then
        let proofRequest  = result.proofRequest
        XCTAssertNotNil(proofRequest)
        XCTAssertNotNil(proofRequest.requestedAttributes)
    }
}
