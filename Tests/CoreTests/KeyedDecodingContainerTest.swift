//
// Copyright contributors to the IBM Verify Core SDK for iOS project
//

@testable import Core
import Foundation
import XCTest

/// Tests the KeyedCodingContainer+Extension functions
class KeyedCodingContainerTests: XCTestCase {
    func testInitInt() {
        // Given, When
        let value = UnknownCodingKeys.init(intValue: 0)
        
        // Then
        XCTAssertNotNil(value)
    }
    
    func testInitString() {
        // Given, When
        let value = UnknownCodingKeys.init(stringValue: "helloworld")
        
        // Then
        XCTAssertNotNil(value)
    }
    
    func testFakeDecodeKeys() {
        let json = "{ \"id\": 2,\"name\": \"John Smith\",\"isActive\": true,\"email\": \"johnsmith@email.com\",\"lat\": 43.951544,\"lng\": 34.46 }"
        
        // Given, When
        let result = try? JSONDecoder().decode(FakeKeyedCoder.self, from: json.data(using: .utf8)!)
        
        // Then
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.additionalData.count, result?.allKeys.count)
    }
    
    func testFakeEncodeKeys() {
        let json = "{\"id\":2,\"name\":\"John Smith\",\"isActive\":true,\"email\":\"johnsmith@email.com\",\"lat\":43.951543999999998,\"lng\":34.460000000000001}"
        
        // Given, When
        let result = try? JSONDecoder().decode(FakeKeyedCoder.self, from: json.data(using: .utf8)!)
        let value = try? JSONEncoder().encode(result)
        let json2 = String(decoding: value!, as: UTF8.self)
        
        // Then
        XCTAssertNotNil(value)
        XCTAssertNotEqual(json2.count, json.count)
    }
    
    func testFake2DecodeKeys() {
        let json = "{ \"id\": 2,\"name\": \"John Smith\",\"isActive\": true,\"email\": \"johnsmith@email.com\",\"lat\": 43.951544,\"lng\": 34.46 }"
        
        // Given, When
        let result = try? JSONDecoder().decode(FakeKeyedCoder2.self, from: json.data(using: .utf8)!)
        
        // Then
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.name, "John Smith")
        XCTAssertEqual(result?.id, 2)
    }
    
    func testFake2EncodeKeys() {
        let json = "{\"id\":2,\"name\":\"John Smith\",\"isActive\":true,\"email\":\"johnsmith@email.com\",\"lat\":43.951543999999998,\"lng\":34.460000000000001}"
        
        // Given, When
        let result = try? JSONDecoder().decode(FakeKeyedCoder2.self, from: json.data(using: .utf8)!)
        let value = try? JSONEncoder().encode(result)
        let json2 = String(decoding: value!, as: UTF8.self)
        
        // Then
        XCTAssertNotNil(value)
        XCTAssertNotEqual(json2.count, json.count)
    }
}

struct FakeKeyedCoder : Codable {
    public let additionalData: [String: Any]
    public let allKeys: [UnknownCodingKeys]
    
    public init(from decoder: Decoder) throws {
        let unknownContainer = try decoder.container(keyedBy: UnknownCodingKeys.self)
        self.additionalData = unknownContainer.decode()
        self.allKeys = unknownContainer.allKeys
    }
    
    public func encode(to encoder: Encoder) throws {
        var rootContainer = encoder.container(keyedBy: UnknownCodingKeys.self)
        try rootContainer.encode(withDictionary: additionalData)
    }
}

struct FakeKeyedCoder2 : Codable {
    public let name: String
    public let id: Int
    public let additionalData: [String: Any]
    public let allKeys: [UnknownCodingKeys]
    
    private enum CodingKeys: String, CodingKey {
        case name
        case id
    }
    
    public init(from decoder: Decoder) throws {
        let rootContainer = try decoder.container(keyedBy: CodingKeys.self)
        self.name = try rootContainer.decode(String.self, forKey: .name)
        self.id = try rootContainer.decode(Int.self, forKey: .id)
        
        let unknownContainer = try decoder.container(keyedBy: UnknownCodingKeys.self)
        self.additionalData = unknownContainer.decode(exclude: CodingKeys.self)
        self.allKeys = unknownContainer.allKeys
    }
    
    public func encode(to encoder: Encoder) throws {
        var unknownContainer = encoder.container(keyedBy: UnknownCodingKeys.self)
        try unknownContainer.encode(withDictionary: additionalData)
        
        var rootContainer = encoder.container(keyedBy: CodingKeys.self)
        try rootContainer.encode(id, forKey: .id)
        try rootContainer.encode(name, forKey: .name)
    }
}


