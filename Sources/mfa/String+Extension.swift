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
        let __: UInt8 = 255
        let alphabet: [UInt8] = [
            __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0x00 - 0x0F
            __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0x10 - 0x1F
            __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0x20 - 0x2F
            __,__,26,27, 28,29,30,31, __,__,__,__, __, 0,__,__,  // 0x30 - 0x3F
            __, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,  // 0x40 - 0x4F
            15,16,17,18, 19,20,21,22, 23,24,25,__, __,__,__,__,  // 0x50 - 0x5F
            __, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,  // 0x60 - 0x6F
            15,16,17,18, 19,20,21,22, 23,24,25,__, __,__,__,__,  // 0x70 - 0x7F
            __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0x80 - 0x8F
            __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0x90 - 0x9F
            __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0xA0 - 0xAF
            __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0xB0 - 0xBF
            __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0xC0 - 0xCF
            __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0xD0 - 0xDF
            __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0xE0 - 0xEF
            __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0xF0 - 0xFF
        ]
        
        let decodedBytes = self.utf8.withContiguousStorageIfAvailable { (sequencePointer) -> [UInt8] in
            guard sequencePointer.count > 0 else {
                return []
            }
        
            let size = (self.utf8.count * 5 + 4) / 8                                            // determine the size of the block
            
            return sequencePointer.withMemoryRebound(to: UInt8.self) { (body) -> [UInt8] in     // access this memory for another type
                return [UInt8](unsafeUninitializedCapacity: size) { result, count in            // create uninitialize array in memory
                    
                    count = alphabet.withUnsafeBufferPointer { decodingTable in                 // use the alphabet sequence to transform body
                        var decodedBaseIndex = 0
                        var bitsLeft: Int = 0
                        var buffer: UInt32 = 0
                        
                        for i in 0 ..< body.count {
                            let index = Int(body[i])
                            let char = decodingTable[index]
                            
                            guard char != __ else {                                             // return where illegal character
                                return 0
                            }
                            
                            guard char != 0x40 else {                                           // continue where character can be ignored
                                continue
                            }

                            buffer <<= 5                                                        // shift the buffer left by 5 bits
                            buffer |= UInt32(char)
                            bitsLeft += 5
                            
                            if bitsLeft >= 8 {                                                  // write sequence to block
                                result[decodedBaseIndex] = UInt8((buffer >> (bitsLeft - 8)) & 0xFF)
                                decodedBaseIndex += 1
                                bitsLeft -= 8
                            }
                        }

                        return decodedBaseIndex
                    }
                }
            }
        }
           
        if let decodedBytes = decodedBytes, decodedBytes.count > 0 {                            // construct Data where bytes are available
            return Data(bytes: decodedBytes, count: decodedBytes.count)
        }
        
        return nil
    }
}
