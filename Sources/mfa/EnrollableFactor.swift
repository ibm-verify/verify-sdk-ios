//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import Foundation

// MARK: Enums

/// An item that represents a factor.
internal enum EnrollableType: String, Codable, Equatable {
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
