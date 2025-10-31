//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import Foundation

// MARK: Enums

/// An item that represents a factor.
internal enum EnrollableType: String, Codable, Equatable {
    /// A one-time passcode based on a time interval.
    case totp
    
    /// A hash-based message authentication algorithm for generating a one-time passcode.
    case hotp
    
    /// A cryptographic key pair for signing data requiring Face ID authentication.
    case face
    
    /// A cryptographic key pair for signing data requiring Touch ID authentication.
    case fingerprint
    
    /// A cryptographic key pair for signing data without requiring biometric authentication.
    case userPresence
}

// MARK: - Protocols

/// A type that describes an enrollable factor.
internal protocol EnrollableFactor {
    /// The location of the enrollment endpoint.
    var uri: URL { get }
    
    /// The type of enrollment method.
    var type: EnrollableType { get }
}

// MARK: - Structures

/// A type that defines a signature enrollment.
internal struct SignatureEnrollableFactor: EnrollableFactor {
    let uri: URL
    let type: EnrollableType
    
    /// The preferred hashing algorithm for the factor to generate the private and public key pairs.
    let algorithm: String
}

/// A type that defines a time-based one-time password (TOTP) enrollment for on-premise.
internal struct OnPremiseTOTPEnrollableFactor: EnrollableFactor {
    let uri: URL
    let type = EnrollableType.totp
}

/// A type that defines a time-based one-time password (TOTP) enrollment for cloud.
internal struct CloudTOTPEnrollableFactor: EnrollableFactor {
    let uri: URL
    let type = EnrollableType.totp
    
    /// An identifier generated during enrollment to uniquely identify a specific authentication method.
    let id: String
    
    /// The algorithm used to calculate the one-time passcode.
    let algorithm: String
    
    /// The secret or seed value Base32  encoded.
    let secret: String
    
    /// The length of digits to display.
    let digits: Int
    
    /// The interval in seconds for `totp` generation.
    let period: Int
}
