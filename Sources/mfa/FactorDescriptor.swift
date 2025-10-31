//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import Foundation
import SwiftUI

// MARK: Enums

/// An item that represents a type of factor.
@dynamicMemberLookup
public enum FactorType {
    /// A hash-based message authentication algorithm for generating a one-time passcode based on a time interval.
    case totp(TOTPFactorInfo)
    
    /// A hash-based message authentication algorithm for generating a one-time passcode.
    case hotp(HOTPFactorInfo)
    
    /// A cryptographic key pair for signing data requiring Face ID authentication.
    case face(FaceFactorInfo)
    
    /// A cryptographic key pair for signing data requiring Touch ID authentication.
    case fingerprint(FingerprintFactorInfo)
    
    /// A cryptographic key pair for signing data without requiring biometric authentication.
    case userPresence(UserPresenceFactorInfo)
}

extension FactorType {
    /// The underlying value type of ``Factor``.
    ///
    /// Demonstrates checking the underlying `valueType` against an array of `FactorType`.
    /// ```swift
    /// // Create a new TOTP factor.
    /// let factor = TOTPFactorInfo(with: "HXDMVJ")
    ///
    /// // Create a new OTP authenticator with the factor.
    /// let authenticator = OTPAuthenticator(with: "ACME Co", accountName: "john.doe@email.com", factor: factor)
    ///
    /// // Retrieve the TOTP factor.
    /// let value = authenticator.allowedFactors[0].valueType as! TOTPFactorInfo
    /// print(value) // HOTPFactorInfo(id: 5B9156..., secret: "HXDMVJ", algorithm: MFA.HashAlgorithmType.sha1, digits: 6, counter: 1)
    /// ```
    public var valueType: any Factor {
        switch self {
        case .totp(let value):
            return value
        case .hotp(let value):
            return value
        case .face(let value):
            return value
        case .fingerprint(let value):
            return value
        case .userPresence(let value):
            return value
        }
    }
}

extension FactorType {
    public subscript<T>(dynamicMember keyPath: KeyPath<any Factor, T>) -> T {
        switch self {
        case .totp(let value):
            return value[keyPath: keyPath]
        case .hotp(let value):
            return value[keyPath: keyPath]
        case .face(let value):
            return value[keyPath: keyPath]
        case .fingerprint(let value):
            return value[keyPath: keyPath]
        case .userPresence(let value):
            return value[keyPath: keyPath]
        }
    }
}

extension FactorType: Codable {
    private enum CodingKeys: CodingKey {
        case totp
        case hotp
        case face
        case fingerprint
        case userPresence
    }
    
    /// Creates a new instance by decoding from the given decoder.
    /// - Parameter decoder: The decoder to read data from.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let key = container.allKeys.first
        
        switch key {
        case .totp:
            self = .totp(try container.decode(TOTPFactorInfo.self, forKey: .totp))
        case .hotp:
            self = .hotp(try container.decode(HOTPFactorInfo.self, forKey: .hotp))
        case .face:
            self = .face(try container.decode(FaceFactorInfo.self, forKey: .face))
        case .fingerprint:
            self = .fingerprint(try container.decode(FingerprintFactorInfo.self, forKey: .fingerprint))
        case .userPresence:
            self = .userPresence(try container.decode(UserPresenceFactorInfo.self, forKey: .userPresence))
        default:
            throw DecodingError.dataCorrupted(DecodingError.Context(codingPath: container.codingPath, debugDescription: "Unable to decode enum."))
        }
    }
    
    /// Encodes this value into the given encoder.
    /// - Parameter encoder: The encoder to write data to.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        switch self {
        case .totp(let value):
            try container.encode(value, forKey: .totp)
        case .hotp(let value):
            try container.encode(value, forKey: .hotp)
        case .face(let value):
            try container.encode(value, forKey: .face)
        case .fingerprint(let value):
            try container.encode(value, forKey: .fingerprint)
        case .userPresence(let value):
            try container.encode(value, forKey: .userPresence)
        }
    }
}

// MARK: - Protocols

/// An interface that a factor registration adhere to.
public protocol Factor: Identifiable, Codable {
    /// An identifier generated during enrollment to uniquely identify a specific authentication method.
    ///
    /// This value is represented as a `UUID`.
    var id: UUID { get }
    
    /// The display name for the factor.
    var displayName: String { get }
}
