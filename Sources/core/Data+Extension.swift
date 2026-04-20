//
// Copyright contributors to the IBM Verify Core SDK for iOS project
//

import Foundation

extension Data {
    /// Returns a Base-58 encoded string  as defined in [draft-msporny-base58-03](https://datatracker.ietf.org/doc/html/draft-msporny-base58-03).
    /// - Returns: The Base-58 encoded string.
    public func base58EncodedString() -> String {
        // 1. Define the Base58 alphabet
        let alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        let base = UInt64(alphabet.count) // 58

        // Handle empty data case
        guard !self.isEmpty else {
            return ""
        }

        // 2. Convert Data to [UInt8] representing the large integer (big-endian)
        var bytes = [UInt8](self)

        // 3. Count leading zeros in the input data
        // Each leading zero byte corresponds to a leading '1' in Base58
        var leadingZeros = 0
        for byte in bytes {
            if byte == 0 {
                leadingZeros += 1
            } else {
                break
            }
        }

        // 4. Perform Base58 conversion (division by 58)
        var encodedIndices = [UInt8]() // Stores remainders (indices into alphabet)
        var carry: UInt64 = 0

        // Keep dividing the number represented by 'bytes' by 58 until it's zero
        while bytes.contains(where: { $0 != 0 }) { // While number > 0
            carry = 0 // Reset carry for each division pass
            var quotient = [UInt8]() // Result of division for the next iteration

            // Iterate through bytes from most significant to least significant
            for byte in bytes {
                // Combine carry with the current byte to form a larger number part
                let currentValue = carry * 256 + UInt64(byte)
                // Calculate the new byte value (quotient part) and the new carry (remainder part)
                let quotientByte = UInt8(currentValue / base)
                carry = currentValue % base // This carry becomes the remainder for the *next* byte

                // Add the quotient byte to the new array, suppressing leading zeros in the quotient
                if !quotient.isEmpty || quotientByte != 0 {
                    quotient.append(quotientByte)
                }
            }

            // The final 'carry' after iterating through all bytes is the remainder for this division pass
            encodedIndices.append(UInt8(carry))

            // The quotient becomes the number for the next division pass
            bytes = quotient
        }

        // 5. Prepend '1's for leading zeros
        // The result needs to be reversed because we collected remainders from least significant
        let prefix = String(repeating: alphabet.first!, count: leadingZeros)
        let encodedChars = encodedIndices.reversed().map { index -> Character in
            let alphabetIndex = alphabet.index(alphabet.startIndex, offsetBy: Int(index))
            return alphabet[alphabetIndex]
        }

        // 6. Combine prefix and encoded characters
        return prefix + String(encodedChars)
    }
    
    /// Returns a Base-64 URL encoded string  as defined in [RFC4648](https://tools.ietf.org/html/rfc4648).
    /// - Parameter options: The options to use for the encoding. Default value is `[]`.
    /// - Returns: The Base-64 URL encoded string.
    public func base64UrlEncodedString(options: Data.Base64EncodingOptions = []) -> String {
        let result = base64EncodedString(options: options)
        let allowedCharacters = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._* +/=")
        
        guard var value = result.addingPercentEncoding(withAllowedCharacters: allowedCharacters) else {
            return ""
        }
        
        if options.contains(Data.Base64EncodingOptions.safeUrlCharacters) {
            value = value.replacingOccurrences(of: " ", with: "%20")
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
        }
        
        if options.contains(Data.Base64EncodingOptions.noPaddingCharacters) {
            value = value.trimmingCharacters(in: ["="])
        }
        
        return value
    }
}

extension Data.Base64EncodingOptions {
    /// Encoder flag bit to indicate using the "URL and filename safe" variant of Base64 (see RFC 3548 section 4) where - and _ are used in place of + and /.
    public static let safeUrlCharacters = Data.Base64EncodingOptions(rawValue: UInt(1 << 9))
    
    /// Encoder flag bit to omit the padding '=' characters at the end of the output (if any).
    public static let noPaddingCharacters = Data.Base64EncodingOptions(rawValue: UInt(1 << 10))
}
