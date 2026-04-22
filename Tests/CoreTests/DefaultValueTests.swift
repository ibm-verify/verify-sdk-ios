//
// Copyright contributors to the IBM Verify Core SDK for iOS project
//

import XCTest
@testable import Core

extension Default.Value {
    /// A zero value.
    public enum Zero: DefaultValue {
        public static var defaultValue: Int { Int.zero }
    }
}

extension Default {
    public typealias ZeroInt = Wrapper<Value.Zero>
}

final class DefaultValueTests: XCTestCase {
    
    // MARK: - Structures
    
    struct Person: Codable {
        let userId: Int
        let name: String
        @Default.True var isTrue: Bool
        @Default.EmptyString var nickName: String
        @Default.False var isEnabled: Bool
        @Default.True var isAdmin: Bool
    }
    
    struct Post: Codable {
        let postId: Int
        let name: String
        @Default.ZeroInt var count: Int
        @Default.EmptyList var tags: [String]
        @Default.EmptyMap var metadata: [String: String]
    }
    
    // MARK: - Enum Unit Tests
    
    /// Tests the raw defaultValue properties of the enums.
    func testDefaultValueEnums() {
        XCTAssertEqual(Default.Value.True.defaultValue, true)
        XCTAssertEqual(Default.Value.False.defaultValue, false)
        XCTAssertEqual(Default.Value.EmptyString.defaultValue, "")
        XCTAssertEqual(Default.Value.Zero.defaultValue, 0)
        
        let emptyList: [String] = Default.Value.EmptyList<[String]>.defaultValue
        XCTAssertTrue(emptyList.isEmpty)
        
        let emptyMap: [String: Int] = Default.Value.EmptyMap<[String: Int]>.defaultValue
        XCTAssertTrue(emptyMap.isEmpty)
    }
    
    // MARK: - Bool Tests
    
    func testDecodeDefaultTrue() throws {
        let json = "{\"userId\": 1, \"name\": \"John\"}"
        let result = try JSONDecoder().decode(Person.self, from: json.data(using: .utf8)!)
        XCTAssertTrue(result.isAdmin)
        XCTAssertTrue(result.isTrue)
    }
    
    func testDecodeDefaultFalse() throws {
        let json = "{\"userId\": 1, \"name\": \"John\"}"
        let result = try JSONDecoder().decode(Person.self, from: json.data(using: .utf8)!)
        XCTAssertFalse(result.isEnabled)
    }
    
    // MARK: - String Tests
    
    func testDecodeDefaultString() throws {
        let json = "{\"userId\": 1, \"name\": \"John\"}"
        let result = try JSONDecoder().decode(Person.self, from: json.data(using: .utf8)!)
        XCTAssertEqual(result.nickName, "")
    }
    
    // MARK: - Collection Tests (List & Map)
    
    func testDecodeDefaultCollections() throws {
        let json = "{\"postId\": 1, \"name\": \"Swift Post\"}"
        let result = try JSONDecoder().decode(Post.self, from: json.data(using: .utf8)!)
        
        XCTAssertEqual(result.tags, [])
        XCTAssertEqual(result.metadata, [:])
    }
    
    func testDecodeProvidedCollections() throws {
        let json = """
        {
            "postId": 1,
            "name": "Swift Post",
            "tags": ["ios"],
            "metadata": {"lang": "en"}
        }
        """
        let result = try JSONDecoder().decode(Post.self, from: json.data(using: .utf8)!)
        
        XCTAssertEqual(result.tags, ["ios"])
        XCTAssertEqual(result.metadata, ["lang": "en"])
    }
    
    // MARK: - Custom Default (ZeroInt)
    
    func testDecodeCustomDefaultInt() throws {
        let json = "{\"postId\": 1, \"name\": \"John\"}"
        let result = try JSONDecoder().decode(Post.self, from: json.data(using: .utf8)!)
        XCTAssertEqual(result.count, 0)
    }
    
    func testDecodeProvidedInt() throws {
        let json = "{\"postId\": 1, \"name\": \"John\", \"count\": 42}"
        let result = try JSONDecoder().decode(Post.self, from: json.data(using: .utf8)!)
        XCTAssertEqual(result.count, 42)
    }
    
    // MARK: - Encode Tests
    
    func testEncodeDefaultAll() throws {
        let person = Person(userId: 1, name: "John")
        let data = try JSONEncoder().encode(person)
        
        // Round-trip verification
        let decoded = try JSONDecoder().decode(Person.self, from: data)
        XCTAssertEqual(decoded.nickName, "")
        XCTAssertTrue(decoded.isAdmin)
        XCTAssertFalse(decoded.isEnabled)
    }
    
    func testEncodeCustomDefaultInt() throws {
        let post = Post(postId: 1, name: "John")
        let data = try JSONEncoder().encode(post)
        
        let decoded = try JSONDecoder().decode(Post.self, from: data)
        XCTAssertEqual(decoded.count, 0)
        XCTAssertEqual(decoded.tags, [])
    }
    
    // MARK: - All Values Integration
    
    func testDecodeAllProvided() throws {
        let json = """
        {
            "userId": 1,
            "name": "John",
            "nickName": "jono",
            "isAdmin": false,
            "isEnabled": true,
            "isTrue": false
        }
        """
        let result = try JSONDecoder().decode(Person.self, from: json.data(using: .utf8)!)
        
        XCTAssertEqual(result.userId, 1)
        XCTAssertEqual(result.name, "John")
        XCTAssertEqual(result.nickName, "jono")
        XCTAssertFalse(result.isAdmin)
        XCTAssertTrue(result.isEnabled)
        XCTAssertFalse(result.isTrue)
    }
}
