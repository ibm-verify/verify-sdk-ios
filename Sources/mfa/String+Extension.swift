//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import Foundation

extension String {
    /// Converts the camel case value as snake case.
    ///
    /// ```swift
    /// print("camelCase".toSnakeCase())
    /// // prints camel_case
    /// ```
    /// - Returns: Where the string can not be represented as snake case the original value is returned.
    public func toSnakeCase() -> String {
        let pattern = "([a-z0-9])([A-Z])"
        let regex = try! NSRegularExpression(pattern: pattern, options: [])
        let range = NSRange(location: 0, length: count)

        return regex.stringByReplacingMatches(in: self, options: [], range: range, withTemplate: "$1_$2").lowercased()
    }
    
    /// Returns Base-32 decoded data.
    ///
    /// ```swift
    /// guard let data = "JBSWY3DPEE======".base32DecodedData() else {
    ///    return
    /// }
    ///
    /// let result = String(decoding: data, as: UTF8.self)
    /// print(result) // print Hello!
    /// ```
    /// - Returns: The Base-32 decoded data. If the decoding fails, returns `nil`.
    public func base32DecodedData() -> Data? {
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        let paddingCharacter: Character = "="
        
        // Precompute lookup table (faster than firstIndex)
        var lookup: [Character: UInt8] = [:]
        for (i, char) in alphabet.enumerated() {
            lookup[char] = UInt8(i)
        }
        
        var buffer: UInt32 = 0
        var bitsRemaining = 0
        var decodedBytes: [UInt8] = []
        
        for char in self.uppercased() {
            if char == paddingCharacter {
                break
            }
            
            // Ignore spaces and common separators
            if char.isWhitespace { continue }
            
            guard let value = lookup[char] else {
                return nil // invalid character
            }
            
            buffer = (buffer << 5) | UInt32(value)
            bitsRemaining += 5
            
            if bitsRemaining >= 8 {
                bitsRemaining -= 8
                let byte = UInt8((buffer >> bitsRemaining) & 0xFF)
                decodedBytes.append(byte)
            }
        }
        
        return Data(decodedBytes)
    }
}
