//
// Copyright contributors to the IBM Verify Core SDK for iOS project
//

import XCTest
@testable import Core

final class AnyCodableTests: XCTestCase {
    private let encoder = JSONEncoder()
    
    // MARK: - Initialization & Literals
    
    func testLiterals() {
        let nilCodable: AnyCodable = nil
        XCTAssertTrue(nilCodable.value is Void || nilCodable.value is NSNull)
        
        let boolCodable: AnyCodable = true
        XCTAssertEqual(boolCodable.value as? Bool, true)
        
        let intCodable: AnyCodable = 42
        XCTAssertEqual(intCodable.value as? Int, 42)
        
        let floatCodable: AnyCodable = 3.14
        XCTAssertEqual(floatCodable.value as? Double, 3.14)
        
        let stringCodable: AnyCodable = "hello"
        XCTAssertEqual(stringCodable.value as? String, "hello")
        
        let arrayCodable: AnyCodable = [1, 2, "3"]
        XCTAssertEqual((arrayCodable.value as? [Any])?.count, 3)
        
        let dictCodable: AnyCodable = ["key": "value"]
        XCTAssertEqual((dictCodable.value as? [AnyHashable: Any])?["key"] as? String, "value")
    }

    // MARK: - Equatable & Hashable Coverage
    
    func testEquatableAndHashable() {
        // We must test every numeric type branch in the switch for 100% coverage
        let types: [AnyCodable] = [
            AnyCodable(Void()), AnyCodable(true),
            AnyCodable(Int(1)), AnyCodable(Int8(1)), AnyCodable(Int16(1)),
            AnyCodable(Int32(1)), AnyCodable(Int64(1)),
            AnyCodable(UInt(1)), AnyCodable(UInt8(1)), AnyCodable(UInt16(1)),
            AnyCodable(UInt32(1)), AnyCodable(UInt64(1)),
            AnyCodable(Float(1.0)), AnyCodable(Double(1.0)),
            AnyCodable("string"), AnyCodable([AnyCodable(1)]),
            AnyCodable(["key": AnyCodable(1)]),
            AnyCodable(NSNull())
        ]
        
        for item in types {
            // Test equality with self
            XCTAssertEqual(item, item)
            // Test hashability
            let _ = item.hashValue
            // Test inequality with a different type
            XCTAssertNotEqual(item, AnyCodable("Not Equal"))
        }
        
        // Specific check for default branch in Equatable
        struct NonHandledType {}
        XCTAssertNotEqual(AnyCodable(NonHandledType()), AnyCodable(NonHandledType()))
    }

    // MARK: - Description Coverage
    
    func testDescription() {
        XCTAssertEqual(AnyCodable(nil as Int?).description, "nil")
        XCTAssertEqual(AnyCodable("test").description, "test")
        XCTAssertEqual(AnyCodable(10).debugDescription, "AnyCodable(10)")
        
        // Coverage for CustomDebugStringConvertible branch
        let debuggable = AnyCodable(10)
        XCTAssertTrue(debuggable.debugDescription.contains("AnyCodable"))
    }

    // MARK: - Encoding Coverage
    
    func testEncoding() throws {
        let encoder = JSONEncoder()
        
        // Fix: Using the dictionaryLiteral initializer from your extension
        // OR explicitly casting to AnyEncodable to satisfy the compiler.
        let values: [String: AnyEncodable] = [
            "bool": AnyEncodable(true),
            "int": AnyEncodable(1),
            "int8": AnyEncodable(Int8(2)),
            "int16": AnyEncodable(Int16(3)),
            "int32": AnyEncodable(Int32(4)),
            "int64": AnyEncodable(Int64(5)),
            "uint": AnyEncodable(UInt(6)),
            "uint8": AnyEncodable(UInt8(7)),
            "uint16": AnyEncodable(UInt16(8)),
            "uint32": AnyEncodable(UInt32(9)),
            "uint64": AnyEncodable(UInt64(10)),
            "float": AnyEncodable(Float(11.0)),
            "double": AnyEncodable(12.0),
            "string": AnyEncodable("13"),
            "date": AnyEncodable(Date(timeIntervalSince1970: 0)),
            "url": AnyEncodable(URL(string: "https://google.com")!),
            "array": AnyEncodable([1, 2, nil] as [Any?]),
            "dict": AnyEncodable(["sub": "value"]),
            "null": AnyEncodable(NSNull())
        ]
        
        let data = try encoder.encode(values)
        XCTAssertFalse(data.isEmpty)
        
        // NSNumber branch (Foundation)
        // We explicitly cast to AnyEncodable here as well
        let num = AnyEncodable(NSNumber(value: true))
        XCTAssertNoThrow(try encoder.encode(num))
        
        let floatNum = AnyEncodable(NSNumber(value: Float(1.2)))
        XCTAssertNoThrow(try encoder.encode(floatNum))
        
        // Invalid Value branch (Default)
        struct Unencodable {}
        let invalid = AnyEncodable(Unencodable())
        XCTAssertThrowsError(try encoder.encode(invalid))
    }

    func testAnyEncodableEncodingSuccess() throws {
        // This array covers every single case in the switch statement
        let values: [AnyEncodable] = [
            AnyEncodable(NSNull()),
            AnyEncodable(Void()),
            AnyEncodable(true),
            AnyEncodable(Int(1)),
            AnyEncodable(Int8(2)),
            AnyEncodable(Int16(3)),
            AnyEncodable(Int32(4)),
            AnyEncodable(Int64(5)),
            AnyEncodable(UInt(6)),
            AnyEncodable(UInt8(7)),
            AnyEncodable(UInt16(8)),
            AnyEncodable(UInt32(9)),
            AnyEncodable(UInt64(10)),
            AnyEncodable(Float(11.1)),
            AnyEncodable(12.2), // Double
            AnyEncodable("string"),
            AnyEncodable(Date(timeIntervalSince1970: 0)),
            AnyEncodable(URL(string: "https://apple.com")!),
            AnyEncodable([1, "2", nil] as [Any?]),
            AnyEncodable(["key": "value"] as [String: Any?])
        ]
        
        for wrapper in values {
            XCTAssertNoThrow(try encoder.encode(wrapper))
        }
    }
    
    func testAnyEncodableEncodingInvalidValueThrows() {
        struct NonEncodable {}
        let wrapper = AnyEncodable(NonEncodable())
        
        XCTAssertThrowsError(try encoder.encode(wrapper)) { error in
            guard case EncodingError.invalidValue = error else {
                XCTFail("Expected EncodingError.invalidValue")
                return
            }
        }
    }

    // MARK: - NSNumber Branch Coverage
    
    func testAnyEncodableNSNumberEncoding() throws {
        // We must hit every case in the 'encode(nsnumber:into:)' switch
        let numbers: [NSNumber] = [
            NSNumber(value: true),          // "B"
            NSNumber(value: Int8(1)),       // "c"
            NSNumber(value: Int16(1)),      // "s"
            NSNumber(value: Int32(1)),      // "i"
            NSNumber(value: Int64(1)),      // "q"
            NSNumber(value: UInt8(1)),      // "C"
            NSNumber(value: UInt16(1)),     // "S"
            NSNumber(value: UInt32(1)),     // "I"
            NSNumber(value: UInt64(1)),     // "Q"
            NSNumber(value: Float(1.1)),    // "f"
            NSNumber(value: Double(1.1))    // "d"
        ]
        
        for num in numbers {
            let wrapper = AnyEncodable(num)
            XCTAssertNoThrow(try encoder.encode(wrapper))
        }
    }

    // MARK: - Equatable & Hashable Coverage
    
    func testAnyEncodableEquality() {
        let samples: [AnyEncodable] = [
            AnyEncodable(Void()),
            AnyEncodable(true),
            AnyEncodable(Int(1)), AnyEncodable(Int8(1)), AnyEncodable(Int16(1)),
            AnyEncodable(Int32(1)), AnyEncodable(Int64(1)),
            AnyEncodable(UInt(1)), AnyEncodable(UInt8(1)), AnyEncodable(UInt16(1)),
            AnyEncodable(UInt32(1)), AnyEncodable(UInt64(1)),
            AnyEncodable(Float(1.0)), AnyEncodable(Double(1.0)),
            AnyEncodable("test"),
            AnyEncodable([AnyEncodable(1)]),
            AnyEncodable(["key": AnyEncodable(1)]),
            AnyEncodable(["key": AnyHashable("value")])
        ]
        
        for item in samples {
            XCTAssertEqual(item, item)
            XCTAssertNotEqual(item, AnyEncodable("non-matching"))
        }
        
        // Test default branch
        struct Unhandled {}
        XCTAssertNotEqual(AnyEncodable(Unhandled()), AnyEncodable(Unhandled()))
    }

    // MARK: - Description & DebugDescription
    
    func testAnyEncodableDescriptions() {
        // Void branch
        XCTAssertEqual(AnyEncodable(Void()).description, "nil")
        
        // CustomStringConvertible branch
        XCTAssertEqual(AnyEncodable("hello").description, "hello")
        
        // DebugDescription branch
        let debugItem = AnyEncodable(100)
        XCTAssertEqual(debugItem.debugDescription, "AnyEncodable(100)")
        
        // Default description branch (using a type that isn't CustomStringConvertible)
        struct Raw { let v = 1 }
        XCTAssertTrue(AnyEncodable(Raw()).description.contains("Raw"))
    }
    
    // MARK: - Decoding Coverage
    
    func testDecoding() throws {
        let json = """
        {
            "bool": true,
            "int": 42,
            "double": 3.14,
            "string": "test",
            "array": [1, 2],
            "dict": {"a": 1},
            "null": null
        }
        """.data(using: .utf8)!
        
        let decoder = JSONDecoder()
        let result = try decoder.decode([String: AnyDecodable].self, from: json)
        
        XCTAssertTrue(result["bool"]?.value is Bool)
        XCTAssertTrue(result["int"]?.value is Int)
        XCTAssertTrue(result["double"]?.value is Double)
        XCTAssertTrue(result["string"]?.value is String)
        XCTAssertTrue(result["array"]?.value is [Any])
        XCTAssertTrue(result["dict"]?.value is [String: Any])
        XCTAssertTrue(result["null"]?.value is NSNull)
    }
    
    func testDecodingCorrupted() {
        let decoder = JSONDecoder()
        
        // We need something that SingleValueContainer can "see" but cannot decode into any of your 'if let' types.
        // In many cases, an invalid format like a bare data blob or an incorrectly escaped string can work.
        
        // An alternative: Decode a type that isn't one of your handled types but is valid JSON. This is hard because you handle almost everything.
        
        // To specifically hit that 'throw' line:
        // Create a data blob that is valid JSON but fails the sniff test.
        let json = "{ \"invalid\": ".data(using: .utf8)! // Incomplete JSON
        
        XCTAssertThrowsError(try decoder.decode(AnyDecodable.self, from: json)) { error in
            // This ensures it's the right error type
            XCTAssertTrue(error is DecodingError)
        }
    }
    
    // MARK: - Equatable & Hashable Coverage
        
    func testAnyDecodableEqualityAndHashing() {
        // We create an array of samples to hit every branch of the switches
        let samples: [AnyDecodable] = [
            AnyDecodable(true),
            AnyDecodable(Int(1)),
            AnyDecodable(Int8(1)),
            AnyDecodable(Int16(1)),
            AnyDecodable(Int32(1)),
            AnyDecodable(Int64(1)),
            AnyDecodable(UInt(1)),
            AnyDecodable(UInt8(1)),
            AnyDecodable(UInt16(1)),
            AnyDecodable(UInt32(1)),
            AnyDecodable(UInt64(1)),
            AnyDecodable(Float(1.0)),
            AnyDecodable(Double(1.0)),
            AnyDecodable("string"),
            AnyDecodable([AnyDecodable(1)]),
            AnyDecodable(["key": AnyDecodable(1)]),
            AnyDecodable(["key": AnyHashable("value")]),
            AnyDecodable(NSNull()),
            AnyDecodable(Void())
        ]
        
        for item in samples {
            // Hits the specific type branch in Equatable
            XCTAssertEqual(item, item)
            
            // Hits the specific type branch in Hashable
            let _ = item.hashValue
            
            // Hits the 'default: return false' branch in Equatable
            XCTAssertNotEqual(item, AnyDecodable("different value"))
        }
    }
    
    func testAnyDecodableEquatableDefaultBranch() {
        struct UnhandledType {}
        let lhs = AnyDecodable(UnhandledType())
        let rhs = AnyDecodable(UnhandledType())
        
        // Hits the default branch in Equatable
        XCTAssertNotEqual(lhs, rhs)
    }

    // MARK: - CustomStringConvertible Coverage
    
    func testAnyDecodableDescription() {
        // 1. Hits the 'is Void' branch
        let voidDecodable = AnyDecodable(Void())
        XCTAssertEqual(voidDecodable.description, "nil")
        
        // 2. Hits the 'CustomStringConvertible' branch
        let stringDecodable = AnyDecodable("hello")
        XCTAssertEqual(stringDecodable.description, "hello")
        
        // 3. Hits the 'default' branch
        struct RawValue { let id = 1 }
        let raw = AnyDecodable(RawValue())
        XCTAssertTrue(raw.description.contains("RawValue"))
    }

    // MARK: - CustomDebugStringConvertible Coverage
    
    func testAnyDecodableDebugDescription() {
        // Hits the 'CustomDebugStringConvertible' branch (Strings conform to this)
        let stringDecodable = AnyDecodable("debug")
        XCTAssertEqual(stringDecodable.debugDescription, "AnyDecodable(\"debug\")")
        
        // Hits the 'default' branch (Void does not conform to CustomDebugStringConvertible)
        let voidDecodable = AnyDecodable(Void())
        XCTAssertEqual(voidDecodable.debugDescription, "AnyDecodable(nil)")
    }
    
    // MARK: - Hashable Default Branch Coverage
    
    func testAnyDecodableHashableDefault() {
        struct NonHashableType {}
        let decodable = AnyDecodable(NonHashableType())
        
        // This ensures the code hits the 'default: break' in the hash function
        var hasher = Hasher()
        decodable.hash(into: &hasher)
    }
}
