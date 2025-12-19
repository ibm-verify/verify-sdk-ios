//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import Foundation
import SwiftUI

// MARK: Enums

/// An item that represents a type of factor.
///
/// This enum uses `@dynamicMemberLookup` to allow direct access to properties of its associated values, provided they conform to the `Factor` protocol. This provides a unified and convenient access point to the underlying factor's properties (e.g., `factorType.id`).
@dynamicMemberLookup
public enum FactorType: Equatable {
    /// A hash-based message authentication algorithm for generating a one-time passcode based on a time interval.
    case totp(TOTPFactorInfo)
    
    /// A hash-based message authentication algorithm for generating a one-time passcode.
    case hotp(HOTPFactorInfo)
    
    /// A cryptographic key pair for signing data requiring biometric authentication.
    case biometric(BiometricFactorInfo)
    
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
        case .biometric(let value):
            return value
        case .userPresence(let value):
            return value
        }
    }
}

extension FactorType {
    /// Allows direct access to the properties of the underlying `Factor` value.
    ///
    /// This is a convenience accessor that forwards property access to the `valueType` property.
    public subscript<T>(dynamicMember keyPath: KeyPath<any Factor, T>) -> T {
        self.valueType[keyPath: keyPath]
    }
}

extension FactorType {
    /// Looks up the name and algorithm for a given biometric and user‑presence factors.
    ///
    /// - Returns: The factor name and hash algorithm for biometric and user presence factors, otherwise `nil`.
    public var nameAndAlgorithm: (name: String, algorithm: SigningAlgorithm)? {
        switch self {
        case .biometric(let value):
            return (name: value.name, algorithm: value.algorithm)
        case .userPresence(let value):
            return (name: value.name, algorithm: value.algorithm)
        default:
            return nil
        }
    }
    
    /// The Keychain identifier associated with this factor, when applicable.
    ///
    /// Biometric and user‑presence factors generate a unique `name` during enrollment, which is used to locate the corresponding Keychain item that stores the cryptographic key pair. This property exposes that identifier in a unified way across supported factor types.
    ///
    /// For factors that do not rely on a Keychain‑backed key pair—such as TOTP or HOTP—this value is `nil`.
    ///
    /// ```swift
    /// if let factor = authenticator.enrolledFactors.first(where: {
    ///    $0.name == transaction.keyName
    /// }) {
    ///    // Found the matching factor
    /// }
    /// ```
    ///
    /// - Returns: The Keychain item name for biometric and user‑presence factors, otherwise `nil`.
    public var name: String? {
        switch self {
        case .biometric(let value):
            return value.name
        case .userPresence(let value):
            return value.name
        default:
            return nil
        }
    }
}

extension FactorType: Codable {
    private enum CodingKeys: String, CodingKey {
        case totp
        case hotp
        case biometric
        case userPresence
    }
    
    /// Creates a new instance by decoding from the given decoder.
    /// - Parameter decoder: The decoder to read data from.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        if let value = try container.decodeIfPresent(TOTPFactorInfo.self, forKey: .totp) {
            self = .totp(value)
        }
        else if let value = try container.decodeIfPresent(HOTPFactorInfo.self, forKey: .hotp) {
            self = .hotp(value)
        }
        else if let value = try container.decodeIfPresent(BiometricFactorInfo.self, forKey: .biometric) {
            self = .biometric(value)
        }
        else if let value = try container.decodeIfPresent(UserPresenceFactorInfo.self, forKey: .userPresence) {
            self = .userPresence(value)
        }
        else {
            throw DecodingError.dataCorruptedError(forKey: .totp, in: container, debugDescription: "No valid factor type found.")
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
        case .biometric(let value):
            try container.encode(value, forKey: .biometric)
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
    var id: String { get }
    
    /// The display name for the factor.
    var displayName: String { get }
    
    /// The system image name to represent the factor.
    var imageName: String { get }
}
