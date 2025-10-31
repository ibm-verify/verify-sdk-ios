//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import Foundation

/// Time-based one-time password (TOTP) that generates a one-time passcode using the current time as a source of uniqueness.
public struct TOTPFactorInfo: Factor {
    /// Initializes the OTP info object to use a one-time passcode based on a time interval.
    /// - Parameters:
    ///   - secret: The secret or seed value Base32  encoded.
    ///   - digits: This value is constrained to `6` or `8` digits in length.  The default is `6`.
    ///   - algorithm: The algorithm used to calculate the one-time passcode.  The default is `sha1`.
    ///   - period: The interval in seconds for `totp` generation.  Default value is `30`.
    ///   
    /// - Remark: A `digits` value less than 6 is not recommended.  Reducing the number of digits for OTP validation presents a potential security risk.
    public init(with secret: String, digits: Int = 6, algorithm: HashAlgorithmType = .sha1, period: Int = 30) {
        self.id = UUID()
        self.secret = secret
        self.algorithm = algorithm
        self.period = (period >= 10 && period <= 300) ? period : 30
        
        // Assign the digits value or default to 6.
        // Assign the digits value or default to 6.
        self.digits = digits > 0 ? digits : 6
    }
    
    public let id: UUID
    
    public let displayName = "Time-based one-time password (TOTP)"
    
    public let secret: String
    
    public let algorithm: HashAlgorithmType
    
    public let digits: Int
    
    /// The interval in seconds for `totp` generation.  Default value is `30`.
    public let period: Int
    
    private enum CodingKeys: String, CodingKey {
        case id
        case secret
        case algorithm
        case digits
        case period
    }
}

extension TOTPFactorInfo: OTPDescriptor {
    /// Generate the new one-time passcode for the authenticator instance.
    public mutating func generatePasscode() -> String {
        // Calculate the value to hash depending on the type of one-time passcode.
        let timeInterval: TimeInterval = Date().timeIntervalSince1970
        let value = UInt64(timeInterval / Double(self.period))

        // Return the one-time passcode based on the hash algorithm.
        return generatePasscode(from: value)
    }
    
    /// Calculates the remaining time for a given period in seconds based on `Date().timeIntervalSince1970`.
    /// - Parameters:
    ///   - seconds: The value in seconds.
    ///
    /// ```swift
    /// let result = TOTPFactorInfo.remainingTime(4)
    /// print(result)
    /// ```
    /// - Returns: The remaining time in seconds.
    public static func remainingTime(_ seconds: TimeInterval = 30) -> Int {
        // fmod gets the modulus dividing Date().timeIntervalSince1970 by seconds.
        let currentTimeRemaining = Int(fmod(Date().timeIntervalSince1970, seconds))
        return Int(seconds) - currentTimeRemaining
    }
}
