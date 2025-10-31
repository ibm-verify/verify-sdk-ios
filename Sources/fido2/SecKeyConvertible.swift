//
// Copyright contributors to the IBM Verify FIDO2 SDK for iOS project
//

import Foundation
/// The interface needed for SecKey conversion.
protocol SecKeyConvertible: CustomStringConvertible {
    /// Creates a key from a raw representation.
    init<D>(rawRepresentation data: D) throws where D: ContiguousBytes
        
    /// A raw representation of the key.
    var rawRepresentation: Data { get }
}

extension SecKeyConvertible {
    /// A string version of the key for visual inspection.
    public var description: String {
        return self.rawRepresentation.withUnsafeBytes { bytes in
            return "Key representation contains \(bytes.count) bytes."
        }
    }
}
