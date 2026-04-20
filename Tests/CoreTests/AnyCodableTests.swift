//
// Copyright contributors to the IBM Verify Core SDK for iOS project
//

import XCTest
import Foundation
@testable import Core

// MARK: - Helper Types and Protocols for Testing

// Replicating internal protocols to satisfy extension constraints in the test environment
@usableFromInline protocol _AnyDecodable {
    var value: Any { get }
    init<T>(_ value: T?)
}

@usableFromInline protocol _AnyEncodable {
    var value: Any { get }
    init<T>(_ value: T?)
}

// A custom type for testing the Encodable/Decodable path
private struct TestStruct: Codable, Equatable, Hashable {
    let id: Int
    let name: String
}

// MARK: - AnyCodable Tests

final class AnyCodableTests: XCTestCase {

    // --- Initialization Tests ---

    func testInitialization_NonOptional() {
        let value = AnyCodable(123)
        XCTAssertEqual(value.value as? Int, 123)
    }

    func testInitialization_Nil() {
        let value = AnyCodable(nil as Int?)
        // Nil should initialize to an empty tuple/Void ()
        XCTAssert(value.value is Void)
    }
    
    // --- Encoding/Decoding (Codable) Tests ---
    
    // This tests the AnyCodable conformity, which relies on both AnyEncodable and AnyDecodable
    func testEncodingAndDecoding_Primitives() throws {
        let original: [String: AnyCodable] = [
            "bool": true,
            "int": 42,
            "double": 3.14,
            "string": "test",
            "null": nil
        ]
        
        let encoder = JSONEncoder()
        let data = try encoder.encode(original)
        
        let decoder = JSONDecoder()
        let decoded = try decoder.decode([String: AnyCodable].self, from: data)
        
        XCTAssertTrue(decoded["bool"]?.value as? Bool ?? (decoded["bool"]?.value as? NSNumber)?.boolValue ?? false, "The decoded 'bool' value must be true.")
        XCTAssertEqual(decoded["int"]?.value as? Int, 42)
        XCTAssertEqual(decoded["double"]?.value as? Double, 3.14)
        XCTAssertEqual(decoded["string"]?.value as? String, "test")
        
        // Check for nil/NSNull decoding path
        #if canImport(Foundation)
        XCTAssert(decoded["null"]?.value is NSNull)
        #else
        XCTAssert(decoded["null"]?.value is Void)
        #endif
    }

    func testEncodingAndDecoding_ComplexTypes() throws {
        let nestedStruct = TestStruct(id: 1, name: "Nested")
        
        // The array literal [1, "two", 3.0] is interpreted as [Any] and then wrapped by AnyCodable().
        let original: [String: AnyCodable] = [
            "array": AnyCodable([1, "two", 3.0] as [Any]),
            "nested_struct": AnyCodable(nestedStruct) // Should fall back to the default Encodable implementation
        ]
        
        let encoder = JSONEncoder()
        let data = try encoder.encode(original)
        
        let decoder = JSONDecoder()
        let decoded = try decoder.decode([String: AnyCodable].self, from: data)
        
        // Test array decoding (requires comparison of the underlying Any array)
        let decodedArray = decoded["array"]?.value as? [Any]
        XCTAssertNotNil(decodedArray)
        XCTAssertEqual(decodedArray?.count, 3)
        XCTAssertEqual(decodedArray?[0] as? Int, 1)
        XCTAssertEqual(decodedArray?[1] as? String, "two")
        
        // Robust check for floating point numbers which might be decoded as Int
        let thirdElement = decodedArray?[2]
        if let doubleValue = thirdElement as? Double {
            XCTAssertEqual(doubleValue, 3.0, accuracy: 0.0001)
        } else if let intValue = thirdElement as? Int {
            XCTAssertEqual(Double(intValue), 3.0, accuracy: 0.0001)
        } else {
            XCTFail("Expected 3.0 (as Double or Int), but found \(String(describing: thirdElement)) of type \(type(of: thirdElement))")
        }
        
        // Test struct decoding - it decodes into a dictionary of [String: Any] or [String: AnyDecodable] which is then mapped to [String: Any]
        let decodedStructDict = decoded["nested_struct"]?.value as? [String: Any]
        XCTAssertEqual(decodedStructDict?["id"] as? Int, 1)
        XCTAssertEqual(decodedStructDict?["name"] as? String, "Nested")
    }

    // --- Equality (Equatable) Tests ---

    func testEquality_SameTypes() {
        XCTAssertEqual(AnyCodable(1), AnyCodable(1))
        XCTAssertEqual(AnyCodable(true), AnyCodable(true))
        XCTAssertEqual(AnyCodable("hello"), AnyCodable("hello"))
        
        // Ensure explicit [String: AnyCodable] comparison path is hit
        let dict1: [String: AnyCodable] = ["a": 1, "b": "two"]
        let dict2: [String: AnyCodable] = ["a": 1, "b": "two"]
        XCTAssertEqual(AnyCodable(dict1), AnyCodable(dict2))
    }

    func testEquality_DifferentTypes() {
        XCTAssertNotEqual(AnyCodable(1), AnyCodable("1"))
        XCTAssertNotEqual(AnyCodable(1.0), AnyCodable(1))
        XCTAssertNotEqual(AnyCodable(true), AnyCodable(0))
    }

    func testEquality_NilAndVoidAndNSNull() {
        // Test case is (Void, Void) in the original code
        XCTAssertEqual(AnyCodable(nil as String?), AnyCodable(nil as Int?))
        
        // Test case is (NSNull, NSNull) in the original code
        #if canImport(Foundation)
        XCTAssertEqual(AnyCodable(NSNull()), AnyCodable(NSNull()))
        #endif
    }
    
    func testEquality_HeterogeneousContainers() {
        // Test cases using NSDictionary/NSArray for comparison (AnyCodable.== line 62, 64)
        
        // Dictionary [String: Any] path
        let dictLHS: [String: Any] = ["a": 1, "b": "two"]
        let dictRHS: [String: Any] = ["a": 1, "b": "two"]
        XCTAssertEqual(AnyCodable(dictLHS), AnyCodable(dictRHS))
        
        let dictRHS_diff: [String: Any] = ["a": 1, "b": "three"]
        XCTAssertNotEqual(AnyCodable(dictLHS), AnyCodable(dictRHS_diff))
        
        // Array [Any] path
        let arrayLHS: [Any] = [1, "two", true]
        let arrayRHS: [Any] = [1, "two", true]
        XCTAssertEqual(AnyCodable(arrayLHS), AnyCodable(arrayRHS))
        
        let arrayRHS_diff: [Any] = [1, "two", false]
        XCTAssertNotEqual(AnyCodable(arrayLHS), AnyCodable(arrayRHS_diff))
    }

    func testEquality_MismatchedCase() {
        let value = AnyCodable(1)
        let diffValue = AnyCodable("hello")
        // This covers the final `default: return false` case
        XCTAssertNotEqual(value, diffValue)
    }

    // --- Hashable Tests ---
    
    func testHashable_Primitives() {
        let values: [AnyCodable] = [
            AnyCodable(true),
            AnyCodable(42),
            AnyCodable(3.14),
            AnyCodable("hashme"),
            AnyCodable(UInt(5)) // Covers all number types via generics/casting
        ]
        
        // Check that two equal instances have the same hash
        XCTAssertEqual(AnyCodable(42).hashValue, AnyCodable(42).hashValue)
        
        // Ensure no crash and the hash method is executed for various types
        values.forEach { _ = $0.hashValue }
    }
    
    func testHashable_Containers() {
        // Explicitly hit the [AnyCodable] hash path
        let array1 = AnyCodable([AnyCodable(1), AnyCodable("a")] as [AnyCodable])
        let array2 = AnyCodable([AnyCodable(1), AnyCodable("a")] as [AnyCodable])
        XCTAssertEqual(array1.hashValue, array2.hashValue)
        
        // Explicitly hit the [String: AnyCodable] hash path
        let dict1 = AnyCodable(["key": AnyCodable(42)] as [String: AnyCodable])
        let dict2 = AnyCodable(["key": AnyCodable(42)] as [String: AnyCodable])
        XCTAssertEqual(dict1.hashValue, dict2.hashValue)
    }

    func testHashable_UnsupportedType() {
        // Test the default: break case in hash(into:)
        class NonHashable {}
        let nonHashable = AnyCodable(NonHashable())
        
        var hasher = Hasher()
        nonHashable.hash(into: &hasher)
    }

    // --- CustomStringConvertible / CustomDebugStringConvertible Tests ---

    func testCustomStringConvertible() {
        // Case 1: is Void
        XCTAssertEqual(AnyCodable(nil as Int?).description, "nil")

        // Case 2: let value as CustomStringConvertible (e.g., String)
        XCTAssertEqual(AnyCodable("test").description, "test")

        // Case 3: default: String(describing: value) (e.g., Array<AnyCodable>)
        let array: [AnyCodable] = [AnyCodable(1), AnyCodable("a")]
        XCTAssertEqual(AnyCodable(array).description, array.description)
    }

    func testCustomDebugStringConvertible() {
        // Case 1: let value as CustomDebugStringConvertible (e.g., String, Int)
        XCTAssertEqual(AnyCodable(123).debugDescription, "AnyCodable(123)")

        // Case 2: default: returns "AnyCodable(\(description))"
        let nonDebugConvertibleArray = [1, 2, 3] // Array is not CustomDebugStringConvertible in Swift Standard Library
        XCTAssertEqual(AnyCodable(nonDebugConvertibleArray).debugDescription, "AnyCodable(\(nonDebugConvertibleArray.description))")
    }
}

// MARK: - AnyDecodable Tests

final class AnyDecodableTests: XCTestCase {

    // Helper for creating Data from JSON string
    private func data(for json: String) -> Data {
        return json.data(using: .utf8)!
    }

    // --- Decoding (_AnyDecodable.init(from:)) Tests ---

    func testDecoding_Boolean() throws {
        let json = data(for: "true")
        let decoded = try JSONDecoder().decode(AnyDecodable.self, from: json)
        XCTAssertEqual(decoded.value as? Bool, true)
    }

    func testDecoding_Int() throws {
        let json = data(for: "123")
        let decoded = try JSONDecoder().decode(AnyDecodable.self, from: json)
        // Int is tried before UInt
        XCTAssertEqual(decoded.value as? Int, 123)
    }
    
    func testDecoding_UInt() throws {
        // Use a value large enough that Int might fail, but UInt won't, ensuring the UInt path is hit.
        let bigUInt: UInt = 9000000000000000000
        let uintJson = data(for: "\(bigUInt)")
        let uintDecoded = try JSONDecoder().decode(AnyDecodable.self, from: uintJson)
        
        // Check for Int, UInt, or Double representation, as JSONDecoder is ambiguous with large integers.
        let decodedValue = uintDecoded.value
        
        if let decodedUInt = decodedValue as? UInt {
            XCTAssertEqual(decodedUInt, bigUInt, "Failed to decode as expected UInt.")
        } else if let decodedInt = decodedValue as? Int {
            XCTAssertEqual(UInt(decodedInt), bigUInt, "Decoded Int value does not match expected UInt.")
        } else if let decodedDouble = decodedValue as? Double {
            XCTAssertEqual(UInt(decodedDouble), bigUInt, "Decoded Double value does not match expected UInt.")
        } else {
            XCTFail("Expected \(bigUInt) (as UInt, Int, or Double), but found \(String(describing: decodedValue)) of type \(type(of: decodedValue))")
        }
    }

    func testDecoding_Double() throws {
        let json = data(for: "1.23")
        let decoded = try JSONDecoder().decode(AnyDecodable.self, from: json)
        XCTAssertEqual(decoded.value as? Double, 1.23)
    }

    func testDecoding_String() throws {
        let json = data(for: "\"hello\"")
        let decoded = try JSONDecoder().decode(AnyDecodable.self, from: json)
        XCTAssertEqual(decoded.value as? String, "hello")
    }

    func testDecoding_Null() throws {
        let json = data(for: "null")
        let decoded = try JSONDecoder().decode(AnyDecodable.self, from: json)
        
        #if canImport(Foundation)
        // Foundation path: NSNull()
        XCTAssert(decoded.value is NSNull)
        #else
        // Non-Foundation path: Optional<Self>.none -> Void ()
        XCTAssert(decoded.value is Void)
        #endif
    }
    
    func testDecoding_Array() throws {
        let json = data(for: "[1, \"two\", true]")
        let decoded = try JSONDecoder().decode(AnyDecodable.self, from: json)
        
        let array = decoded.value as? [Any]
        XCTAssertNotNil(array)
        XCTAssertEqual(array?.count, 3)
        XCTAssertEqual(array?[0] as? Int, 1)
        XCTAssertEqual(array?[1] as? String, "two")
        // Decoded bools might be represented as Int (0 or 1) depending on underlying Codable implementation,
        // but here we check for the type it should settle on (Bool).
        XCTAssertEqual(array?[2] as? Bool, true)
    }
    
    func testDecoding_Dictionary() throws {
        let json = data(for: "{\"key1\": 100, \"key2\": \"value\"}")
        let decoded = try JSONDecoder().decode(AnyDecodable.self, from: json)
        
        let dict = decoded.value as? [String: Any]
        XCTAssertNotNil(dict)
        XCTAssertEqual(dict?.count, 2)
        XCTAssertEqual(dict?["key1"] as? Int, 100)
        XCTAssertEqual(dict?["key2"] as? String, "value")
    }

    func testDecoding_CustomStructSuccess() throws {
        // Encoding a custom struct produces a JSON dictionary. AnyDecodable should successfully
        // decode this dictionary into a standard Swift dictionary ([String: Any]).
        
        let customStruct = TestStruct(id: 99, name: "corrupt")
        let data = try JSONEncoder().encode(customStruct)
        
        let decoded = try JSONDecoder().decode(AnyDecodable.self, from: data)
        
        // FIX: Casting to [String: Any] as the inner values are decoded as primitives, not AnyDecodable wrappers.
        let dict = decoded.value as? [String: Any]
        XCTAssertNotNil(dict, "Expected TestStruct to be decoded as a dictionary ([String: Any]).")
        XCTAssertEqual(dict?["id"] as? Int, 99)
        XCTAssertEqual(dict?["name"] as? String, "corrupt")
    }

    // --- Equatable Tests ---

    func testDecodable_Equality() {
        XCTAssertEqual(AnyDecodable(1), AnyDecodable(1))
        
        // Array of AnyDecodable path
        let array1 = AnyDecodable([AnyDecodable(1), AnyDecodable(true)] as [AnyDecodable])
        let array2 = AnyDecodable([AnyDecodable(1), AnyDecodable(true)] as [AnyDecodable])
        XCTAssertEqual(array1, array2)
        XCTAssertNotEqual(AnyDecodable(1), AnyDecodable(2))
    }
    
    func testDecodable_Equality_HeterogeneousDictionary() {
        // Test case using [String: AnyHashable] comparison (AnyDecodable.== line 192)
        let dict1: [String: AnyHashable] = ["a": 1, "b": "two"]
        let dict2: [String: AnyHashable] = ["a": 1, "b": "two"]
        XCTAssertEqual(AnyDecodable(dict1), AnyDecodable(dict2))
    }
    
    func testDecodable_Equality_MismatchedCase() {
        // Covers the final `default: return false` case
        XCTAssertNotEqual(AnyDecodable(1), AnyDecodable("hello"))
    }
    
    // --- Hashable Tests ---
    
    func testDecodable_Hashable() {
        XCTAssertEqual(AnyDecodable(42).hashValue, AnyDecodable(42).hashValue)
        
        // Ensure array/dictionary hash paths are hit
        let array1 = AnyDecodable([AnyDecodable(1), AnyDecodable("a")] as [AnyDecodable])
        let array2 = AnyDecodable([AnyDecodable(1), AnyDecodable("a")] as [AnyDecodable])
        XCTAssertEqual(array1.hashValue, array2.hashValue)
        
        let dict1 = AnyDecodable(["key": AnyDecodable(42)] as [String: AnyDecodable])
        let dict2 = AnyDecodable(["key": AnyDecodable(42)] as [String: AnyDecodable])
        XCTAssertEqual(dict1.hashValue, dict2.hashValue)
    }
    
    func testDecodable_Hashable_UnsupportedType() {
        // Test the default: break case in hash(into:)
        class NonHashable {}
        let nonHashable = AnyDecodable(NonHashable())
        
        var hasher = Hasher()
        nonHashable.hash(into: &hasher)
    }

    // --- CustomStringConvertible / CustomDebugStringConvertible Tests (Identical to AnyCodable) ---
    
    func testDecodable_CustomStringConvertible() {
        XCTAssertEqual(AnyDecodable(nil as Int?).description, "nil")
        XCTAssertEqual(AnyDecodable("test").description, "test")
    }

    func testDecodable_CustomDebugStringConvertible() {
        XCTAssertEqual(AnyDecodable(123).debugDescription, "AnyDecodable(123)")
    }
}

// MARK: - AnyEncodable Tests

final class AnyEncodableTests: XCTestCase {
    
    // --- Initialization Tests (Identical to AnyCodable) ---
    
    func testInitialization_NonOptional() {
        let value = AnyEncodable(123)
        XCTAssertEqual(value.value as? Int, 123)
    }

    func testInitialization_Nil() {
        let value = AnyEncodable(nil as Int?)
        // Nil should initialize to an empty tuple/Void ()
        XCTAssert(value.value is Void)
    }

    // --- Encoding (_AnyEncodable.encode(to:)) Tests ---

    func testEncoding_PrimitivesAndVoid() throws {
        // Case: is Void
        XCTAssertNoThrow(try JSONEncoder().encode(AnyEncodable(nil as Int?)))
        
        // Primitives
        XCTAssertNoThrow(try JSONEncoder().encode(AnyEncodable(true))) // bool
        XCTAssertNoThrow(try JSONEncoder().encode(AnyEncodable(Int.max))) // int
        XCTAssertNoThrow(try JSONEncoder().encode(AnyEncodable(Int8.max))) // int8
        XCTAssertNoThrow(try JSONEncoder().encode(AnyEncodable(Int16.max))) // int16
        XCTAssertNoThrow(try JSONEncoder().encode(AnyEncodable(Int32.max))) // int32
        XCTAssertNoThrow(try JSONEncoder().encode(AnyEncodable(Int64.max))) // int64
        XCTAssertNoThrow(try JSONEncoder().encode(AnyEncodable(UInt.max))) // uint
        XCTAssertNoThrow(try JSONEncoder().encode(AnyEncodable(UInt8.max))) // uint8
        XCTAssertNoThrow(try JSONEncoder().encode(AnyEncodable(UInt16.max))) // uint16
        XCTAssertNoThrow(try JSONEncoder().encode(AnyEncodable(UInt32.max))) // uint32
        XCTAssertNoThrow(try JSONEncoder().encode(AnyEncodable(UInt64.max))) // uint64
        XCTAssertNoThrow(try JSONEncoder().encode(AnyEncodable(Float(3.14)))) // float
        XCTAssertNoThrow(try JSONEncoder().encode(AnyEncodable(3.14159))) // double
        XCTAssertNoThrow(try JSONEncoder().encode(AnyEncodable("string"))) // string
    }

    func testEncoding_FoundationTypes() throws {
        // All Foundation-dependent paths should be tested
        
        // Case: NSNull
        #if canImport(Foundation)
        XCTAssertNoThrow(try JSONEncoder().encode(AnyEncodable(NSNull())))
        #endif
        
        // Case: Date
        #if canImport(Foundation)
        XCTAssertNoThrow(try JSONEncoder().encode(AnyEncodable(Date())))
        #endif
        
        // Case: URL
        #if canImport(Foundation)
        XCTAssertNoThrow(try JSONEncoder().encode(AnyEncodable(URL(string: "https://example.com")!)))
        #endif
    }
    
    func testEncoding_NSNumber_TypePaths() throws {
        #if canImport(Foundation)
        // This tests the private `encode(nsnumber:into:)` function and its switch statement
        
        // B (Bool)
        let boolNumber = NSNumber(value: true)
        XCTAssertNoThrow(try JSONEncoder().encode(AnyEncodable(boolNumber)))
        
        // c (Int8)
        let charNumber = NSNumber(value: Int8(5))
        XCTAssertNoThrow(try JSONEncoder().encode(AnyEncodable(charNumber)))

        // s (Int16)
        let shortNumber = NSNumber(value: Int16(500))
        XCTAssertNoThrow(try JSONEncoder().encode(AnyEncodable(shortNumber)))
        
        // i (Int32)
        let intNumber = NSNumber(value: Int32(50000))
        XCTAssertNoThrow(try JSONEncoder().encode(AnyEncodable(intNumber)))
        
        // q (Int64)
        let longLongNumber = NSNumber(value: Int64(5000000000))
        XCTAssertNoThrow(try JSONEncoder().encode(AnyEncodable(longLongNumber)))
        
        // C (UInt8)
        let ucharNumber = NSNumber(value: UInt8(5))
        XCTAssertNoThrow(try JSONEncoder().encode(AnyEncodable(ucharNumber)))

        // S (UInt16)
        let ushortNumber = NSNumber(value: UInt16(500))
        XCTAssertNoThrow(try JSONEncoder().encode(AnyEncodable(ushortNumber)))
        
        // I (UInt32)
        let uintNumber = NSNumber(value: UInt32(50000))
        XCTAssertNoThrow(try JSONEncoder().encode(AnyEncodable(uintNumber)))
        
        // Q (UInt64)
        let ulongLongNumber = NSNumber(value: UInt64(5000000000))
        XCTAssertNoThrow(try JSONEncoder().encode(AnyEncodable(ulongLongNumber)))

        // f (Float)
        let floatNumber = NSNumber(value: Float(1.5))
        XCTAssertNoThrow(try JSONEncoder().encode(AnyEncodable(floatNumber)))
        
        // d (Double)
        let doubleNumber = NSNumber(value: 2.5)
        XCTAssertNoThrow(try JSONEncoder().encode(AnyEncodable(doubleNumber)))
        
        // Note: The 'default' case for unsupported NSNumber objCType is not practically reachable
        // with standard Swift number conversions, so we assume coverage through the explicit cases.
        #endif
    }

    func testEncoding_Containers() throws {
        // Case: let array as [Any?]
        let arrayValue: [Any?] = [1, "two", nil]
        XCTAssertNoThrow(try JSONEncoder().encode(AnyEncodable(arrayValue)))
        
        // Case: let dictionary as [String: Any?]
        let dictValue: [String: Any?] = ["key1": 1, "key2": nil, "key3": "three"]
        XCTAssertNoThrow(try JSONEncoder().encode(AnyEncodable(dictValue)))
    }

    func testEncoding_EncodableType() throws {
        // Case: let encodable as Encodable
        let customStruct = TestStruct(id: 1, name: "Test")
        let data = try JSONEncoder().encode(AnyEncodable(customStruct))
        
        let decoded = try JSONDecoder().decode(TestStruct.self, from: data)
        XCTAssertEqual(decoded, customStruct)
    }

    func testEncoding_InvalidValue() {
        // Case: default: throw EncodingError.invalidValue
        // Non-Encodable, non-primitive custom type
        struct NonCodable {}
        
        let nonEncodable = AnyEncodable(NonCodable())
        
        XCTAssertThrowsError(try JSONEncoder().encode(nonEncodable)) { error in
            guard case EncodingError.invalidValue(_, let context) = error else {
                return XCTFail("Expected invalidValue error")
            }
            XCTAssert(context.debugDescription.contains("AnyEncodable value cannot be encoded."))
        }
    }
    
    // --- Literal Protocols (_AnyEncodable extension) Tests ---
    
    func testLiteralProtocols() {
        // ExpressibleByNilLiteral
        let nilLiteral: AnyEncodable = nil
        XCTAssert(nilLiteral.value is Void)
        
        // ExpressibleByBooleanLiteral
        let boolLiteral: AnyEncodable = true
        XCTAssertEqual(boolLiteral.value as? Bool, true)
        
        // ExpressibleByIntegerLiteral
        let intLiteral: AnyEncodable = 123
        XCTAssertEqual(intLiteral.value as? Int, 123)
        
        // ExpressibleByFloatLiteral
        let floatLiteral: AnyEncodable = 4.56
        XCTAssertEqual(floatLiteral.value as? Double, 4.56)
        
        // ExpressibleByStringLiteral / ExpressibleByExtendedGraphemeClusterLiteral
        let stringLiteral: AnyEncodable = "abc"
        XCTAssertEqual(stringLiteral.value as? String, "abc")
        
        // ExpressibleByArrayLiteral
        let arrayLiteral: AnyEncodable = [1, "two", true]
        let array = arrayLiteral.value as? [Any]
        XCTAssertEqual(array?.count, 3)
        XCTAssertEqual(array?[0] as? Int, 1)
        
        // ExpressibleByDictionaryLiteral
        let dictLiteral: AnyEncodable = ["key": 1, 2: "val"]
        let dict = dictLiteral.value as? [AnyHashable: Any]
        XCTAssertEqual(dict?.count, 2)
        XCTAssertEqual(dict?["key"] as? Int, 1)
        XCTAssertEqual(dict?[2] as? String, "val")
    }
}
