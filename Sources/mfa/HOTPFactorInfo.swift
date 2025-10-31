//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import Foundation

/// HMAC-based one-time password (HOTP) is a one-time passcode based on hash-based message authentication codes (HMAC) where each generated code is a single use authentication attempt.
public struct HOTPFactorInfo: Factor {
    /// Initializes the OTP info object to use a hash-based message authentication.
    /// - Parameters:
    ///   - secret: The secret or seed value Base32  encoded.
    ///   - digits: This value is constrained to `6` or `8` digits in length.  The default is `6`.
    ///   - algorithm: The algorithm used to calculate the one-time passcode.  The default is `sha1`.
    ///   - counter: The counter for `hotp` generation.  Default value is `1`.
    ///
    /// - Remark: A `digits` value less than 6 is not recommended.  Reducing the number of digits for OTP validation presents a potential security risk.
    public init(with secret: String, digits: Int = 6, algorithm: HashAlgorithmType = .sha1, counter: Int = 1) {
        self.id = UUID()
        self.secret = secret
        self.algorithm = algorithm
        self.counter = counter > 0 ? counter : 1
        
        // Assign the digits value or default to 6.
        self.digits = digits > 0 ? digits : 6
    }
    
    public let id: UUID
    
    public let displayName = "HMAC-based one-time password (HOTP)"
        
    public let secret: String
    
    public let algorithm: HashAlgorithmType
                                                     
    public let digits: Int
    
    /// The current counter for `hotp` generation.  Default value is `1`.
    public private(set) var counter: Int
    
    private enum CodingKeys: String, CodingKey {
        case id
        case secret
        case algorithm
        case digits
        case counter
    }
}

extension HOTPFactorInfo: OTPDescriptor {
    /// Generate the new one-time passcode for the authenticator instance.
    ///
    /// The ``counter`` value is incremented by `1`.
    public mutating func generatePasscode() -> String {
        // Calculate the value to hash depending on the type of one-time passcode.
        let value = UInt64(self.counter)

        // Generate the one-time passcode based on the hash algorithm.
        let result = generatePasscode(from: value)
        
        // Increment the counter
        self.counter += 1
        
        return result
    }
}
