//
// Copyright contributors to the IBM Verify Core SDK for iOS project
//

import XCTest
import Core

extension Default.Value {
    ///A zero value.
    public enum Zero: DefaultValue {
        public static var defaultValue: Int { Int.zero }
    }
}

extension Default {
    public typealias ZeroInt = Wrapper<Value.Zero>
}

class DefaultValueTests: XCTestCase {
    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    // MARK: Structures
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
    }
    
    // MARK: - Bool Tests
    
    /// Adds  `True` as the `isEnabled` default value.
    func testDecodeDefaultTrue() throws {
        // Given
        let json = """
        {
            "userId": 1,
            "name": "John",
            "nickName": "jono"
        }
        """
        
        do {
            // When
            let result = try JSONDecoder().decode(Person.self, from: json.data(using: .utf8)!)
            
            // Then
            XCTAssertTrue(result.isAdmin)
        }
        catch let error {
            print("Error: \(error.localizedDescription)")
            XCTFail()
        }
    }
    
    /// Adds  `False` as the `isEnabled` default value.
    func testDecodeDefaultFalse() throws {
        // Given
        let json = """
        {
            "userId": 1,
            "name": "John",
            "nickName": "jono"
        }
        """
        
        do {
            // When
            let result = try JSONDecoder().decode(Person.self, from: json.data(using: .utf8)!)
            
            // Then
            XCTAssertFalse(result.isEnabled)
        }
        catch let error {
            print("Error: \(error.localizedDescription)")
            XCTFail()
        }
    }
    
    // MARK: - String Tests
    
    /// Adds  `""` as the `nickName` default value.
    func testDecodeDefaultString() throws {
        // Given
        let json = """
        {
            "userId": 1,
            "name": "John",
            "isAdmin": true,
            "isEnabled": true
        }
        """
        
        do {
            // When
            let result = try JSONDecoder().decode(Person.self, from: json.data(using: .utf8)!)
            
            // Then
            XCTAssertTrue(result.nickName.isEmpty)
        }
        catch let error {
            print("Error: \(error.localizedDescription)")
            XCTFail()
        }
    }
    
    // MARK: - All Values
    /// Checks all values in the JSON defaults and provided.
    func testDecodeAll() throws {
        // Given
        let json = """
        {
            "userId": 1,
            "name": "John",
            "nickName": "jono",
            "isAdmin": false,
            "isEnabled": true
        }
        """
        
        do {
            // When
            let result = try JSONDecoder().decode(Person.self, from: json.data(using: .utf8)!)
            
            // Then
            XCTAssertEqual(result.userId, 1)
            XCTAssertEqual(result.name, "John")
            XCTAssertTrue(result.isEnabled)
            XCTAssertEqual(result.nickName, "jono")
            XCTAssertFalse(result.isAdmin)
        }
        catch let error {
            print("Error: \(error.localizedDescription)")
            XCTFail()
        }
    }
        
    /// Checks all values in the JSON defaults.
    func testDecodeDefaultAll() throws {
        // Given
        let json = """
        {
            "userId": 1,
            "name": "John"
        }
        """
        
        do {
            // When
            let result = try JSONDecoder().decode(Person.self, from: json.data(using: .utf8)!)
            
            // Then
            XCTAssertEqual(result.userId, 1)
            XCTAssertEqual(result.name, "John")
            XCTAssertFalse(result.isEnabled)
            XCTAssertEqual(result.nickName, "")
            XCTAssertTrue(result.isAdmin)
        }
        catch let error {
            print("Error: \(error.localizedDescription)")
            XCTFail()
        }
    }
    
    // MARK: - Custom Default
    /// Custom default `Int.Zero`
    func testDecodeCustomDefaultInt() throws {
        // Given
        let json = """
        {
            "postId": 1,
            "name": "John"
        }
        """
        
        do {
            // When
            let result = try JSONDecoder().decode(Post.self, from: json.data(using: .utf8)!)
            
            // Then
            XCTAssertEqual(result.count, Int.zero)
        }
        catch let error {
            print("Error: \(error.localizedDescription)")
            XCTFail()
        }
    }
    
    /// Custom decode `Int`.
    func testDecodeCustomDefaultAll() throws {
        // Given
        let json = """
        {
            "postId": 1,
            "name": "John",
            "count": 3
        }
        """
        
        do {
            // When
            let result = try JSONDecoder().decode(Post.self, from: json.data(using: .utf8)!)
            
            // Then
            XCTAssertEqual(result.count, 3)
        }
        catch let error {
            print("Error: \(error.localizedDescription)")
            XCTFail()
        }
    }
    
    // MARK: - JSON Encode.
    func testEncodeDefaultAll() throws {
        // Given
        let person = Person(userId: 1, name: "John")
        
        do {
            // When
            let result = try JSONEncoder().encode(person)
            
            // Then
            XCTAssertNotNil(result)
            
            // Then - take the encoded JSON and deecode into a new Person object.
            let newPerson = try JSONDecoder().decode(Person.self, from: result)
            
            // Then - Check the default values are encoded.
            XCTAssertFalse(newPerson.isEnabled)
            XCTAssertEqual(newPerson.nickName, "")
            XCTAssertTrue(newPerson.isAdmin)
        }
        catch let error {
            print("Error: \(error.localizedDescription)")
            XCTFail()
        }
    }
    
    func testEncodeDefaultString() throws {
        // Given
        let person = Person(userId: 1, name: "John")
        
        do {
            // When
            let result = try JSONEncoder().encode(person)
            
            // Then
            XCTAssertNotNil(result)
            
            // Then - take the encoded JSON and deecode into a new Person object.
            let newPerson = try JSONDecoder().decode(Person.self, from: result)
            
            // Then - Check the default values are encoded.
            XCTAssertFalse(newPerson.isEnabled)
            XCTAssertEqual(newPerson.nickName, "")
            XCTAssertTrue(newPerson.isAdmin)
        }
        catch let error {
            print("Error: \(error.localizedDescription)")
            XCTFail()
        }
    }
    
    
    func testEncodeCustomDefaultInt() throws {
        // Given
        let post = Post(postId: 1, name: "John")
        
        do {
            // When
            let result = try JSONEncoder().encode(post)
            
            // Then
            XCTAssertNotNil(result)
            
            // Then - take the encoded JSON and deecode into a new Post object.
            let newPost = try JSONDecoder().decode(Post.self, from: result)
            
            // Then - Check the default values are encoded.
            XCTAssertEqual(newPost.count, 0)
        }
        catch let error {
            print("Error: \(error.localizedDescription)")
            XCTFail()
        }
    }
}
