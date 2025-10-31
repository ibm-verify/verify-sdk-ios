//
// Copyright contributors to the IBM Verify Core SDK for iOS project
//

import Foundation

extension KeyedDecodingContainer {
    /// Decodes a value of the given type for the given key.
    /// - Parameters:
    ///   - type: The type of value to decode.
    ///   - key: The key that the decoded value is associated with.
    /// - Returns: A decoded value of the requested type, or a default value if the `Decoder` does not have an entry associated with the given key, or if the value is a null value.
    public func decode<T>(_ type: Default.Wrapper<T>.Type, forKey key: Key) throws -> Default.Wrapper<T> {
        try decodeIfPresent(type, forKey: key) ?? .init()
    }
    
    /// Decodes a value of the given type for the given key.
    /// - Parameters:
    ///   - type: The type of value to decode.
    ///   - keys: The array of keys that the decoded value is associated with.
    /// - Returns: A value of the requested type, if present for the given key and convertible to the requested type.
    public func decode<T>(_ type: T.Type, forKeys keys: [K]) throws -> T where T: Decodable {
        for key in keys {
            if let value = try? self.decode(type, forKey: key) {
                return value
            }
        }
        
        throw DecodingError.typeMismatch(T.self, DecodingError.Context(codingPath: self.codingPath, debugDescription: "Invalid key for CodingKeys"))
    }
    
    /// Decodes a value of the given type for the given key, if present.
    ///
    /// This method returns `nil` if the container does not have a value
    /// associated with `key`, or if the value is null. The difference between
    /// these states can be distinguished with a `contains(_:)` call.
    ///
    /// - Parameters:
    ///   - type: The type of value to decode.
    ///   - keys: The array of keys that the decoded value is associated with.
    /// - Returns: A decoded value of the requested type, or `nil` if the
    ///   `Decoder` does not have an entry associated with the given key, or if
    ///   the value is a null value.
    public func decodeIfPresent<T>(_ type: T.Type, forKeys keys: [K]) throws -> T? where T : Decodable {
        for key in keys {
            if let value = try? self.decode(type, forKey: key) {
                return value
            }
        }
        
        return nil
    }
}

// MARK: - Unknown Coding Key

/// A  type that can be used as a generic key for unknown encoding and decoding operations.
public struct UnknownCodingKeys: CodingKey {
    // MARK: Fields

    public var stringValue: String
    public var intValue: Int?

    // MARK: Initializers

    /// Creates a new instance from the specified string.
    /// - Parameter stringValue: The string value of the desired key.
    public init?(stringValue: String) {
        self.stringValue = stringValue
    }

    /// Creates a new instance from the specified integer.
    /// - Parameter intValue: The integer value of the desired key.
    public init?(intValue: Int) {
        self.init(stringValue: "")
        self.intValue = intValue
    }
}

/// Extends a container that provides a view into an decoder’s storage, making the encoded properties of an decodable type accessible by keys.
extension KeyedDecodingContainer where Key == UnknownCodingKeys {
    /// Returns the data stored for `AdditionalDataCodingKey` as represented in an dictionary of `[String: Any]`.
    /// - Parameter forKey: The `CodingKey` type to exclude from the decoding.
    /// - Returns: A dictionary of `[String: Any]`.
    public func decode<T: CodingKey>(exclude forKey: T.Type) -> [String: Any] {
        var data = [String: Any]()

        for key in allKeys {
            if forKey.init(stringValue: key.stringValue) == nil {
                if let value = try? decode(String.self, forKey: key) {
                    data[key.stringValue] = value
                }
                else if let value = try? decode(Bool.self, forKey: key) {
                    data[key.stringValue] = value
                }
                else if let value = try? decode(Int.self, forKey: key) {
                    data[key.stringValue] = value
                }
                else if let value = try? decode(Double.self, forKey: key) {
                    data[key.stringValue] = value
                }
                else if let value = try? decode(Float.self, forKey: key) {
                    data[key.stringValue] = value
                }
            }
        }

        return data
    }

    /// Returns the data stored as a dictionary of `[String: Any]`.
    /// - Returns: A dictionary of `[String:Any]`.
    public func decode() -> [String: Any] {
        var data = [String: Any]()

        for key in allKeys {
            if let value = try? decode(String.self, forKey: key) {
                data[key.stringValue] = value
            }
            else if let value = try? decode(Bool.self, forKey: key) {
                data[key.stringValue] = value
            }
            else if let value = try? decode(Int.self, forKey: key) {
                data[key.stringValue] = value
            }
            else if let value = try? decode(Double.self, forKey: key) {
                data[key.stringValue] = value
            }
            else if let value = try? decode(Float.self, forKey: key) {
                data[key.stringValue] = value
            }
        }

        return data
    }
}

/// Extends a container that provides a view into an encoder’s storage, making the decoded properties of an encodable type accessible by keys.
extension KeyedEncodingContainer where Key == UnknownCodingKeys {
    /// Encodes data stored as dictionary of `[String: Any]`.
    /// - Parameter data: A dictionary of `[String: Any]`.
    mutating public func encode(withDictionary data: [String: Any]) throws {
        for (key, value) in data {
            let codingKey = UnknownCodingKeys(stringValue: key)!

            switch value {
            case let value as String: try encode(value, forKey: codingKey)
            case let value as Int: try encode(value, forKey: codingKey)
            case let value as Double: try encode(value, forKey: codingKey)
            case let value as Float: try encode(value, forKey: codingKey)
            case let value as Bool: try encode(value, forKey: codingKey)
            case let value as Encodable: try value.encode(to: superEncoder(forKey: codingKey))
            default: break
            }
        }
    }
}
