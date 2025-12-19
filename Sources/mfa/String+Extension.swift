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
        let paddingCharacter = Character("=")
        
        var buffer = 0
        var bitsRemaining = 0
        var decodedBytes = [UInt8]()

        for char in self {
            if char == paddingCharacter {
                break
            }

            guard let index = alphabet.firstIndex(of: char)?.utf16Offset(in: alphabet) else {
                return nil                                                  // return where illegal character
            }

            buffer = (buffer << 5) | index                                  // shift the buffer left by 5 bits
            bitsRemaining += 5

            if bitsRemaining >= 8 {
                bitsRemaining -= 8
                let byte = UInt8((buffer >> bitsRemaining) & 0xFF)          // write sequence to block
                decodedBytes.append(byte)
            }
        }

        return Data(decodedBytes)                                           // Construct Data where bytes are available
    }
}
