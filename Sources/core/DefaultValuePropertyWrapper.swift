//
// Copyright contributors to the IBM Verify Core SDK for iOS project
//

import Foundation

/// An ordered, random-access collection.
///
/// `List` is a type alias for the `Decodable` and `ExpressibleByArrayLiteral` protocols. When you use `List` as a type or a generic constraint, it matches any type that conforms to both protocols.
public typealias List = Decodable & ExpressibleByArrayLiteral

/// A collection whose elements are key-value pairs.
///
/// `Map` is a type alias for the `Decodable` and `ExpressibleByDictionaryLiteral` protocols. When you use `Map` as a type or a generic constraint, it matches any type that conforms to both protocols.
public typealias Map = Decodable & ExpressibleByDictionaryLiteral

/// An interface for assigning a default value to a decodable element.
///
/// Extend the `DefaultValue` protocol to implement other default values for types supporting decodable.
/// ```swift
/// extension Default.Value {
///    /// A zero value.
///    public enum Zero: DefaultValue {
///       public static var defaultValue: Int { Int.zero }
///    }
/// }
/// 
/// extension Default {
///    /// The zero value.
///    public typealias IntZero = Wrapper<Value.Zero>
/// }
/// ```
public protocol DefaultValue {
    /// The  type supporting a `Decodable` value.
    associatedtype Value: Decodable

    /// The default to use when an element is not defined.
    static var defaultValue: Value {
        get
    }
}

/// A wrapper that allows for default values to be used supporting `JSONDecoder`.
///
/// The `@Default` attribute allows for properties to contain a default value if the JSON element does not exist in the container.
/// ```swift
/// let json = """
/// {
///   "firstName": "John",
///   "lastName": "Smith"
/// }
/// """
///
/// struct Person: Decodable {
///   let firstName: String
///   @Default.EmptyString var lastName: String
///   @Default.EmptyString var nickName: String
///   @Default.False var isEnabled: Bool
///   @Default.EmptyList var alias: [String]
/// }
///
/// if let result = try? JSONDecoder().decode(Person.self, from: json.data(using: .utf8)!) {
///   print(result.lastName)            // prints Smith
///   print(result.nickName.isEmpty)    // prints true
///   print(result.isEnabled)           // prints false
///   print(result.alias)               // prints []
/// }
/// ```
public enum Default {}

/// A wrapper that allows for default values to be used supporting `JSONDecoder`.
extension Default {
    /// A wrapper of the underlying object that can create a default value for a decodable element.
    @propertyWrapper public struct Wrapper<T: DefaultValue> {
        /// The default to use when an element is not defined or the value is missing.
        public var wrappedValue: T.Value
        
        /// Initializes a new instance of `Default`.
        public init() {
            self.wrappedValue = T.defaultValue
        }
    }
}

/// A wrapper that allows for default values to be used supporting `Decodable`.
extension Default.Wrapper: Decodable where T.Value: Decodable {
    /// Creates a new instance by decoding from the given decoder.
    /// - Parameter decoder: The decoder to read data from.
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        self.wrappedValue = try container.decode(T.Value.self)
    }
}

/// A wrapper that allows for default values to be used supporting `Encodable`.
extension Default.Wrapper: Encodable where T.Value: Encodable {
    /// Encodes this value into the given encoder.
    /// - Parameter encoder: The encoder to write data to.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.wrappedValue)
    }
}

/// A wrapper that allows for default values to be used supporting `Equatable`.
extension Default.Wrapper: Equatable where T.Value: Equatable {}

/// A wrapper that allows for default values to be used supporting `Hashable`.
extension Default.Wrapper: Hashable where T.Value: Hashable {}
