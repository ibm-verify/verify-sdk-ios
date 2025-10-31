//
// Copyright contributors to the IBM Verify Core SDK for iOS project
//

import Foundation

extension Default {
    /// A container for default values.
    ///
    /// This enum should not be called directly from your code. Use the type alias references.
    ///
    /// ```swift
    /// struct Person: Decodable {
    ///   let firstName: String
    ///   @Default.EmptyString var lastName: String
    ///   @Default.EmptyString var nickName: String
    ///   @Default.False var isEnabled: Bool
    ///   @Default.EmptyList var alias: [String]
    /// }
    /// ```
    public enum Value {
        /// A Boolean value that’s true.
        public enum True: DefaultValue {
            public static var defaultValue: Bool { true }
        }

        /// A Boolean value that’s false..
        public enum False: DefaultValue {
            public static var defaultValue: Bool { false }
        }

        /// An initialized String with an empty value.
        public enum EmptyString: DefaultValue {
            public static var defaultValue: String { "" }
        }

        /// An initialized Array with with no elements.
        public enum EmptyList<T: List>: DefaultValue {
            public static var defaultValue: T { [] }
        }

        /// An initialized Dictionary with with no elements.
        public enum EmptyMap<T: Map>: DefaultValue {
            public static var defaultValue: T { [:] }
        }
    }
}

extension Default {
    /// A true value.
    public typealias True = Wrapper<Value.True>
    
    /// A false value.
    public typealias False = Wrapper<Value.False>
    
    /// An empty string value.
    public typealias EmptyString = Wrapper<Value.EmptyString>
    
    /// An empty array value.
    public typealias EmptyList<T: List> = Wrapper<Value.EmptyList<T>>
    
    /// An empty dictionary value.
    public typealias EmptyMap<T: Map> = Wrapper<Value.EmptyMap<T>>
}
