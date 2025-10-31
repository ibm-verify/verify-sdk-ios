//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import Foundation
import CryptoKit

/// An interface for providing a mechanism to generate a one-time passcode
public protocol OTPDescriptor {
    /// An arbitrary key value encoded in Base32. Secrets should be at least 160 bits.
    var secret: String { get }
                                                     
    /// The length of a one-time passcode. The value is either 6 or 8. The default is 6.
    var digits: Int { get }
    
    /// The algorithm used to calculate the one-time passcode.  The default is `sha1`.
    var algorithm: HashAlgorithmType { get }
    
    /// Generates a one-time passcode for the authenticator instance.
    /// - Parameters:
    ///   - value: The value used for the generation.
    /// - Returns: The generated one-time passcode.
    mutating func generatePasscode(from value: UInt64) -> String
}

extension OTPDescriptor {
    public func generatePasscode(from value: UInt64) -> String {
        guard let secretData = secret.base32DecodedData() else {
            return ""
        }
        
        /// Computes a message authentication code for the given data.
        /// - Parameters:
        ///     - hashAlgorithm: The HashFunction protocol adopters like SHA256, SHA384, or SHA512.
        /// - Returns: The generated one-time passcode.
        func computeAuthenticationCode<T: HashFunction>(using hashAlgorithm: T) -> String {
            let hash = HMAC<T>.authenticationCode(for: counterData, using: SymmetricKey(data: secretData))
            
            let offset = Int(hash.suffix(1)[0] & 0x0f)
            let hash32 = hash
                .dropFirst(offset)
                .prefix(4)
                .reduce(0, { ($0 << 8) | UInt32($1) })
            
            let hash31 = hash32 & 0x7FFF_FFFF
            let pad = String(repeating: "0", count: digits)
            
            return String((pad + String(hash31)).suffix(digits))
        }
        
        var counter = value.bigEndian
        let counterData = withUnsafeBytes(of: &counter) { Array($0) }
        
        // Return the one-time passcode based on the hash algorithm.
        switch self.algorithm {
        case .sha1:
            return computeAuthenticationCode(using: Insecure.SHA1())
        case .sha256:
            return computeAuthenticationCode(using: SHA256())
        case .sha384:
            return computeAuthenticationCode(using: SHA384())
        case .sha512:
            return computeAuthenticationCode(using: SHA512())
        }
    }
}
