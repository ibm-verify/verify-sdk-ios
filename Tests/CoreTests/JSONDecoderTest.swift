//
// Copyright contributors to the IBM Verify Core SDK for iOS project
//

@testable import Core
import Foundation
import XCTest

/// Tests the KeyedCodingContainer+Extension functions
class JSONDecoderTests: XCTestCase {
    func testDecodeArray() async throws {
        // Given
        let json = """
            { 
                "count": 1,
                "items": [{
                    "id": 1,
                    "name": "John Smith"
                },
                {
                    "id": 2,
                    "name": "Jane Doe"
                }
            ]
        }
        """
        
        
        // Where
        let items = try JSONDecoder().decode(type: [FakeKeyedCoder3].self, from: json.data(using: .utf8)!)
        
        // Then
        XCTAssertNotNil(items)
        
        // Then
        XCTAssertEqual(items.count, 2)
    }
    
    func testDecodeArrayEmpty() async throws {
        let json = """
            {
                "id": 2,
                "items:": []
            }
        """
        
        // Where
        let items = try JSONDecoder().decode(type: [FakeKeyedCoder3].self, from: json.data(using: .utf8)!)
        
        // Then
        XCTAssertNotNil(items)
        
        // Then
        XCTAssertEqual(items.count, 0)
    }
    
    func testDecodeArrayInvalid() async throws {
        let json = """
            { 
                "id": 2,
                "items:": [ "John Smith", "Jane Doe" ]
            }
        """
        
        // Given, When
        let decoder = JSONDecoder()
        
        // Where
        XCTAssertThrowsError(try decoder.decode(type: [FakeKeyedCoder3].self, from: json.data(using: .utf8)!)) { error in
            XCTAssertTrue(error is DecodingError)
        }
    }
}

struct FakeKeyedCoder3 : Codable {
    public let name: String
    public let id: Int
}


