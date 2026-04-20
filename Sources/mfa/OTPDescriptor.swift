//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import Foundation
import CryptoKit

/// An interface for providing a mechanism to generate a one-time passcode
public protocol OTPDescriptor: Hashable, Sendable {
    /// An arbitrary key value encoded in Base32. Secrets should be at least 160 bits.
    var secret: String { get }
                                                     
    /// The length of a one-time passcode. The value is either 6 or 8. The default is 6.
    var digits: Int { get }
    
    /// The algorithm used to calculate the one-time passcode.  The default is `sha1`.
    var algorithm: SigningAlgorithm { get }
    
    /// Generates a one-time passcode for the authenticator instance.
    /// - Parameters:
    ///   - value: The value used for the generation.
    /// - Returns: The generated one-time passcode.
    func generatePasscode(from value: UInt64) -> String
}

extension OTPDescriptor {
    /// Generates a human-readable one-time passcode from a moving factor.
    ///
    /// This implementation conforms to RFC 4226 (HOTP) and RFC 6238 (TOTP) standards. It uses a local truncation helper to handle various HMAC output lengths (SHA1, SHA256, etc.) and ensures memory alignment safety during dynamic truncation.
    ///
    /// - Parameter value: The moving factor. For TOTP, this is the time-step; for HOTP, the counter.
    /// - Returns: A string representation of the passcode, zero-padded to the required length.
    public func generatePasscode(from value: UInt64) -> String {
        guard let secretData = secret.base32DecodedData(), !secretData.isEmpty else { return "" }
        
        let key = SymmetricKey(data: secretData)
        var counter = value.bigEndian
        let counterData = withUnsafeBytes(of: &counter) { Data($0) }
        
        func truncate(_ authCode: some MessageAuthenticationCode) -> UInt32 {
            authCode.withUnsafeBytes { ptr -> UInt32 in
                let offset = Int(ptr.last! & 0x0f)
                // SAFE: loadUnaligned handles offset 5, 13, etc.
                let bigEndianUInt32 = ptr.loadUnaligned(fromByteOffset: offset, as: UInt32.self)
                return UInt32(bigEndian: bigEndianUInt32) & 0x7FFF_FFFF
            }
        }
        
        let code: UInt32
        switch algorithm {
        case .sha1:   code = truncate(HMAC<Insecure.SHA1>.authenticationCode(for: counterData, using: key))
        case .sha256: code = truncate(HMAC<SHA256>.authenticationCode(for: counterData, using: key))
        case .sha384: code = truncate(HMAC<SHA384>.authenticationCode(for: counterData, using: key))
        case .sha512: code = truncate(HMAC<SHA512>.authenticationCode(for: counterData, using: key))
        }
        
        let otpValue = code % UInt32(pow(10, Double(digits)))
        let otpString = String(otpValue)
        
        // SAFE: Native padding avoids C-vararg stack corruption
        return String(repeating: "0", count: max(0, Int(digits) - otpString.count)) + otpString
    }
}
