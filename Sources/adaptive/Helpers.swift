//
// Copyright contributors to the IBM Verify Adaptive SDK for iOS project
//

import Foundation
import Combine

/// Constants for managing common names.
internal struct Constants {
    /// The name of the session identifier.
    static let SessionId = "sessionId"
    
    /// The name of the session renewal interval.
    static let RenewSessionIdInterval = "renewSessionIdInterval"
    
    /// The name of the session renewal timestamp.
    static let RenewSessionIdTimestamp = "renewSessionIdTimestamp"
    
    // The AdaptiveKit bundle identifier name.
    static let BundleIdentifier = "com.ibm.security.verifysdk.adaptive"
    
    // The error description when the `collectionService` has not been assigned.
    static let UnassignedCollectionService = "An instance of AdaptiveCollectionService was not assigned to AdaptiveContext.shared.collectionService."
}

/// A property wrapper to manage storage of values in `UserDefaults`.
@propertyWrapper
public struct UserDefault<T> {
    /// The key that identifies the value.
    var key: String
    
    /// The value associated with key.
    var value: T
    
    /// Initializes the property wrapper.
    /// - Parameters:
    ///   - key: The key that identifies the value.
    ///   - value: The value associated with key.
    public init(key: String, value: T) {
        self.key = key
        self.value = value
        UserDefaults.standard.set(value, forKey: key)
    }
    
    /// The value stored in `UserDefaults`.
    public var wrappedValue: T {
        set {
            UserDefaults.standard.set(newValue, forKey: key)
        }
        get {
            UserDefaults.standard.object(forKey: key) as? T ?? value
        }
    }
}

// MARK: JSON Decoder

/// Structure to represent JSON coding keys as `String`.
struct JSONCodingKeys: CodingKey {
    var stringValue: String

    /// Creates a new instance from the given string.
    /// - Remark: If the string passed as `stringValue` does not correspond to any instance of this type, the result is `nil`.
    /// - Parameter stringValue: The string value of the desired key.
    init?(stringValue: String) {
        self.stringValue = stringValue
    }

    /// The value to use in an integer-indexed collection (e.g. an int-keyed dictionary).
    var intValue: Int?

    /// Creates a new instance from the specified integer.
    /// - Remark: If the value passed as `intValue` does not correspond to any instance of this type, the result is `nil`.
    /// - Parameter intValue: The integer value of the desired key.
    init?(intValue: Int) {
        self.init(stringValue: "\(intValue)")
        self.intValue = intValue
    }
}

// MARK: JSON Decoder Extensions

extension KeyedDecodingContainer {
    /// Decodes a value of `Dictionary<String, Any>` type for the given key.
    /// - Parameters:
    ///   - type: The type of value to decode.
    ///   - key: The key that the decoded value is associated with.
    /// - Returns: A value of the requested type, if present for the given key and convertible to the requested type.
    func decode(_ type: Dictionary<String, Any>.Type, forKey key: K) throws -> Dictionary<String, Any> {
        let container = try self.nestedContainer(keyedBy: JSONCodingKeys.self, forKey: key)
        return try container.decode(type)
    }

    /// Decodes a value of `Dictionary<String, Any>` type for the given key, if present.
    /// - Remark: This method returns `nil` if the container does not have a value associated with `key`, or if the value is null. The difference between these states can be distinguished with a `contains(_:)` call.
    /// - Parameters:
    ///   - type: The type of value to decode.
    ///   - key: The key that the decoded value is associated with.
    /// - Returns: A decoded value of the requested type, or `nil` if the `Decoder` does not have an entry associated with the given key, or if the value is a null value.
    func decodeIfPresent(_ type: Dictionary<String, Any>.Type, forKey key: K) throws -> Dictionary<String, Any>? {
        guard contains(key) else {
            return nil
        }
        return try decode(type, forKey: key)
    }

    /// Decodes a value of `Array<Any>` type for the given key.
    /// - Parameters:
    ///   - type: The type of value to decode.
    ///   - key: The key that the decoded value is associated with.
    /// - Returns: A value of the requested type, if present for the given key and convertible to the requested type.
    func decode(_ type: Array<Any>.Type, forKey key: K) throws -> Array<Any> {
        var container = try self.nestedUnkeyedContainer(forKey: key)
        return try container.decode(type)
    }

    /// Decodes a value of `Array<Any>` type for the given key, if present.
    /// - Remark: This method returns `nil` if the container does not have a value associated with `key`, or if the value is null. The difference between these states can be distinguished with a `contains(_:)` call.
    /// - Parameters:
    ///   - type: The type of value to decode.
    ///   - key: The key that the decoded value is associated with.
    /// - Returns: A decoded value of the requested type, or `nil` if the `Decoder` does not have an entry associated with the given key, or if the value is a null value.
    func decodeIfPresent(_ type: Array<Any>.Type, forKey key: K) throws -> Array<Any>? {
        guard contains(key) else {
            return nil
        }
        return try decode(type, forKey: key)
    }

    /// Decodes a value of `Dictionary<String, Any>` type for the given key.
    /// - Remark: This method returns `nil` if the container does not have a value associated with `key`, or if the value is null. The difference between these states can be distinguished with a `contains(_:)` call.
    /// - Parameters:
    ///   - type: The type of value to decode.
    ///   - key: The key that the decoded value is associated with.
    /// - Returns: A decoded value of the requested type, or `nil` if the `Decoder` does not have an entry associated with the given key, or if the value is a null value.
    func decode(_ type: Dictionary<String, Any>.Type) throws -> Dictionary<String, Any> {
        var dictionary = Dictionary<String, Any>()

        for key in allKeys {
            if let boolValue = try? decode(Bool.self, forKey: key) {
                dictionary[key.stringValue] = boolValue
            }
            else if let stringValue = try? decode(String.self, forKey: key) {
                dictionary[key.stringValue] = stringValue
            }
            else if let intValue = try? decode(Int.self, forKey: key) {
                dictionary[key.stringValue] = intValue
            }
            else if let doubleValue = try? decode(Double.self, forKey: key) {
                dictionary[key.stringValue] = doubleValue
            }
            else if let nestedDictionary = try? decode(Dictionary<String, Any>.self, forKey: key) {
                dictionary[key.stringValue] = nestedDictionary
            }
            else if let nestedArray = try? decode(Array<Any>.self, forKey: key) {
                dictionary[key.stringValue] = nestedArray
            }
        }
        return dictionary
    }
}

extension UnkeyedDecodingContainer {
    /// Decodes a value of an `Array<Any>` type.
    /// - Parameter type: An `Array<Any>`  type value to decode.
    /// - Returns: A value of the requested type, if present for the given key and convertible to the requested type.
    mutating func decode(_ type: Array<Any>.Type) throws -> Array<Any> {
        var array: [Any] = []
        while isAtEnd == false {
            if let value = try? decode(Bool.self) {
                array.append(value)
            }
            else if let value = try? decode(Double.self) {
                array.append(value)
            }
            else if let value = try? decode(String.self) {
                array.append(value)
            }
            else if let nestedDictionary = try? decode(Dictionary<String, Any>.self) {
                array.append(nestedDictionary)
            }
            else if let nestedArray = try? decode(Array<Any>.self) {
                array.append(nestedArray)
            }
        }
        return array
    }

    /// Decodes a value of an `Dictionary<String, Any>` type.
    /// - Parameter type: An `Dictionary<String, Any>`  type value to decode.
    /// - Returns: A value of the requested type, if present for the given key and convertible to the requested type.
   mutating func decode(_ type: Dictionary<String, Any>.Type) throws -> Dictionary<String, Any> {
        let nestedContainer = try self.nestedContainer(keyedBy: JSONCodingKeys.self)
        return try nestedContainer.decode(type)
    }
}
