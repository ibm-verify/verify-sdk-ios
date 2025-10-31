//
// Copyright contributors to the IBM Verify DC SDK for iOS project
//

import XCTest
@testable import Core
@testable import DC

final class ProofRequesTests: XCTestCase {
    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    // MARK: Proof requests

    /// Tests the initiation of the `ProofRequest` from JSON.
    func testInitiate() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.proof")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let result = try decoder.decode(ProofRequest.self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertEqual(result.name, "Citizen-didweb-1726180337209-verifier")
        XCTAssertEqual(result.version, "0.0.1")
        XCTAssertNotNil(result.requestedAttributes)
        XCTAssertNil(result.credentialFilters)
        XCTAssertNotNil(result.properties)
        XCTAssertNil(result.requestedPredicate)
    }
    
    /// Tests the initiation of an array of `ProofRequest` from JSON.
    func testInitiateArray() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.proofs")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let result = try decoder.decode(type: [ProofRequest].self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertEqual(result.count, 2)
    }
    
    /// Tests the initiation of an array of `ProofRequest` from JSON where the structure is not present and throws exception.
    func testInitiateArrayFail() async throws {
        // Given
        let data = """
            { "count": 1 }
        """.data(using: .utf8)!
        
        
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        XCTAssertThrowsError(try decoder.decode(type: [ProofRequest].self, from: data)) { error in
            XCTAssertTrue(error is DecodingError)
        }
    }
    
    /// Tests the initiation of an array of `ProofRequest` from JSON where the the array is empty.
    func testInitiateArrayEmpty() async throws {
        // Given
        let data = """
            { "count": 1, "items": [] }
        """.data(using: .utf8)!
        
        
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let result = try decoder.decode(type: [ProofRequest].self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertEqual(result.count, 0)
    }
    
    // MARK: Proof Predicate
    
    /// Tests the initiation of the `ProofRequest` from JSON.
    func testInitiateWithProofPredicate() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.proof-predicate")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let result = try decoder.decode(ProofRequest.self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        guard let predicate = result.requestedPredicate else {
            XCTFail("No predicate in JSON payload.")
            return
        }
        
        XCTAssertNotNil(predicate)
        XCTAssertEqual(predicate.name, "First name")
        XCTAssertEqual(predicate.type, .equal)
        XCTAssertEqual(predicate.value, "John")
    }
    
    // MARK: Credential filter
    
    /// Tests the initiation of the `ProofRequest` from JSON.
    func testInitiateWithCredentialFilter() async throws {
        // Given
        let data = MockURLProtocol.loadFile(file: "user.proof-predicate")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        
        // Where
        let result = try decoder.decode(ProofRequest.self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        XCTAssertNotNil(result.credentialFilters)
        
        let filter = result.credentialFilters![0]
        XCTAssertEqual(filter.attributeName, "class")
        XCTAssertTrue(filter.attributeValues.isEmpty)
        XCTAssertEqual(filter.proofRequestReferent, "Study Class Referent")
        XCTAssertEqual(filter.exclude,true)
    }
    
    // MARK: Proof predicates
    
    /// Tests the initiation of `ProofRequestPredicate`with a ">" type  from JSON.
    func testInitiateWithProofPredicateGreaterThan() async throws {
        // Given
        let data = """
        {
            "name": "First name",
            "p_type": ">",
            "p_value": "John"
        }
        """.data(using: .utf8)!
        
        let decoder = JSONDecoder()
        
        // Where
        let result = try decoder.decode(ProofRequest.Predicate.self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertEqual(result.type, .greaterThan)
    }
    
    /// Tests the initiation of `ProofRequestPredicate`with a ">=" type  from JSON.
    func testInitiateWithProofPredicateGreaterThanOrEqual() async throws {
        // Given
        let data = """
        {
            "name": "First name",
            "p_type": ">=",
            "p_value": "John"
        }
        """.data(using: .utf8)!
        
        let decoder = JSONDecoder()
        
        // Where
        let result = try decoder.decode(ProofRequest.Predicate.self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertEqual(result.type, .greaterThanOrEqual)
    }
    
    /// Tests the initiation of `ProofRequestPredicate`with a "=" type  from JSON.
    func testInitiateWithProofPredicateEqual() async throws {
        // Given
        let data = """
        {
            "name": "First name",
            "p_type": "=",
            "p_value": "John"
        }
        """.data(using: .utf8)!
        
        let decoder = JSONDecoder()
        
        // Where
        let result = try decoder.decode(ProofRequest.Predicate.self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertEqual(result.type, .equal)
    }
    
    /// Tests the initiation of `ProofRequestPredicate`with a "!=" type  from JSON.
    func testInitiateWithProofPredicateNotEqual() async throws {
        // Given
        let data = """
        {
            "name": "First name",
            "p_type": "!=",
            "p_value": "John"
        }
        """.data(using: .utf8)!
        
        let decoder = JSONDecoder()
        
        // Where
        let result = try decoder.decode(ProofRequest.Predicate.self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertEqual(result.type, .notEqual)
    }
    
    /// Tests the initiation of `ProofRequestPredicate`with a "<" type  from JSON.
    func testInitiateWithProofPredicateLessThan() async throws {
        // Given
        let data = """
        {
            "name": "First name",
            "p_type": "<",
            "p_value": "John"
        }
        """.data(using: .utf8)!
        
        let decoder = JSONDecoder()
        
        // Where
        let result = try decoder.decode(ProofRequest.Predicate.self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertEqual(result.type, .lessThan)
    }
    
    /// Tests the initiation of `ProofRequestPredicate`with a "<=" type  from JSON.
    func testInitiateWithProofPredicateLessThanOrEqual() async throws {
        // Given
        let data = """
        {
            "name": "First name",
            "p_type": "<=",
            "p_value": "John"
        }
        """.data(using: .utf8)!
        
        let decoder = JSONDecoder()
        
        // Where
        let result = try decoder.decode(ProofRequest.Predicate.self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertEqual(result.type, .lessThanOrEqual)
    }
    
    // MARK: Proof Credential Filter
    /// Tests the initiation of `CredentialFilter`with no attribute values  from JSON.
    func testInitiateWithCredentialFilterValues() async throws {
        // Given
        let data = """
        {
            "attr_name": "class",
            "attr_values": ["name", "address"],
            "proof_request_referent": "Study Class Referent",
            "exclude": true
        }
        """.data(using: .utf8)!
        
        let decoder = JSONDecoder()
        
        // Where
        let result = try decoder.decode(ProofRequest.CredentialFilter.self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertTrue(result.attributeValues.count == 2)
    }
    
    /// Tests the initiation of `CredentialFilter`with default `exclude` value **false**  from JSON.
    func testInitiateWithCredentialFilterDefaultExclude() async throws {
        // Given
        let data = """
        {
            "attr_name": "class",
            "attr_values": [],
            "proof_request_referent": "Study Class Referent"
                
        }
        """.data(using: .utf8)!
        
        let decoder = JSONDecoder()
        
        // Where
        let result = try decoder.decode(ProofRequest.CredentialFilter.self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertFalse(result.exclude)
    }
    
    // Tests the initiation of `CredentialFilter`with no referent value from JSON.
    func testInitiateWithCredentialFilterNoReferent() async throws {
        // Given
        let data = """
        {
            "attr_name": "class",
            "attr_values": [],
        }
        """.data(using: .utf8)!
        
        let decoder = JSONDecoder()
        
        // Where
        let result = try decoder.decode(ProofRequest.CredentialFilter.self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertNil(result.proofRequestReferent)
    }
    
    // MARK:  Submission requirements
    
    // Tests the initiation of `SubmissionRequirement` from JSON.
    func testInitiateWithSubmissionRequirements() async throws {
        // Given
        let data = """
        {
            "name": "Confirm banking relationship or employment and residence proofs",
            "purpose": "Recent bank statements or proofs of both employment and residence will be validated to initiate your loan application but not stored",
            "rule": "pick",
            "count": 1,
            "from_nested": [
                { "rule": "all", "from": "A" },
                { "rule": "pick", "count": 2, "from": "B" }
            ]
        }
        """.data(using: .utf8)!
        
        let decoder = JSONDecoder()
        
        // Where
        let result = try decoder.decode(ProofRequest.PresentationRequest.PresentationDefinition.SubmissionRequirement.self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertEqual(result.name, "Confirm banking relationship or employment and residence proofs")
        XCTAssertEqual(result.purpose, "Recent bank statements or proofs of both employment and residence will be validated to initiate your loan application but not stored")
        XCTAssertEqual(result.rule, ProofRequest.PresentationRequest.PresentationDefinition.SubmissionRequirement.RuleType.pick)
        XCTAssertEqual(result.count, 1)
        XCTAssertNil(result.from)
        XCTAssertNil(result.max)
        XCTAssertNil(result.min)
        
        if let fromNested = result.fromNester {
            XCTAssertEqual(fromNested.count, 2)
            XCTAssertEqual(fromNested[0].rule, .all)
            XCTAssertEqual(fromNested[0].from, "A")
            XCTAssertEqual(fromNested[1].rule, .pick)
            XCTAssertEqual(fromNested[1].from, "B")
            XCTAssertEqual(fromNested[1].count, 2)
        }
    }
    
    // MARK:  Input descriptor
    
    // Tests the initiation of `InputDescriptor`with no referent value from JSON.
    func testInitiateWithInputDescriptor() async throws {
        // Given
        let data = """
        {
            "id": "5417b4d6-db87-4d66-88a9-a4346ed8103c",
            "name": "University Degree Certificate",
            "purpose": "Must be educated to apply",
            "group": ["Students", "Staff"],
            "schema": [{
                "uri": "https://w3id.org/security/suites/ed25519-2020/v1",
                "required": true
            }],
            "issuance": [{
                "manifest": "string",
                "additionalProp1": "string",
                "additionalProp2": "string",
                "additionalProp3": "string"
            }],
            "constraints": {
                "limit_disclosure": "required",
                "statuses": {
                    "active": {
                        "directive": "required"
                    }
                },
                "fields": [{
                    "id": "string",
                    "path": ["string"],
                    "purpose": "string",
                    "filter": {
                        "const": true,
                        "enum": [true, 0, "string"],
                        "exclusiveMinimum": "one",
                        "exclusiveMaximum": 0,
                        "format": "string",
                        "minLength": 0,
                        "maxLength": "One",
                        "minimum": 0,
                        "maximum": 0,
                        "not": {},
                        "pattern": "string",
                        "type": "string"
                    },
                    "predicate": "required"
                }],
                "subject_is_issuer": "required",
                "is_holder": [{
                    "field_id": ["string"],
                    "directive": "required"
                }],
                "same_subject": [{
                    "field_id": ["string"],
                    "directive": "required"
                }]
            }
        }
        """.data(using: .utf8)!
        
        let decoder = JSONDecoder()
        
        // Where
        let result = try decoder.decode(ProofRequest.PresentationRequest.PresentationDefinition.InputDescriptor.self, from: data)
        
        // Then
        XCTAssertNotNil(result)
        
        // Then
        XCTAssertEqual(result.name, "University Degree Certificate")
        XCTAssertEqual(result.purpose, "Must be educated to apply")
        XCTAssertEqual(result.purpose, "Must be educated to apply")
        XCTAssertEqual(result.group?.count, 2)
        XCTAssertEqual(result.schema?.count, 1)
        
        
        if let constraints = result.constraints, let fields = constraints.fields {
            // Constraints
            XCTAssertEqual(constraints.limitDisclosure, .required)
            XCTAssertEqual(constraints.statuses, .active(directive: "required"))
            
            // Fields
            XCTAssertEqual(fields.count, 1)
            
            let field = fields[0]
            XCTAssertEqual(field.id, "string")
            XCTAssertEqual(field.path.count, 1)
            XCTAssertEqual(field.purpose, "string")
            XCTAssertEqual(field.predicate, .required)
            
            // Filter
            XCTAssertNotNil(field.filter)
        }
    }
}
