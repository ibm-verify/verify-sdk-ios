//
// Copyright contributors to the IBM Verify FIDO2 SDK for iOS project
//

import Foundation
import os.log
import CryptoKit

// MARK: Foundation Extensions
extension UUID {
    /// Returns the UUID as a byte array.
    var uuidArray: [UInt8] {
        let mirror = Mirror(reflecting: self.uuid)
        return mirror.children.map({ $0.value }) as! [UInt8]
    }
    
    /// Returns a UUID whose structure is all zeros.
    public var empty: UUID {
        return UUID(uuidString: "00000000-0000-0000-0000-000000000000")!
    }
}

extension Data {
    /// Returns a Base-64 URL encoded string.
    /// - Remark: Base-64 URL encoded string removes instances of `=`  and replaces `+` with `-` and `/` with `_`.
    func base64URLEncodedString() -> String {
        return self.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

// MARK: os.log Extensions

extension OSLog {
    private static var subsystem = Bundle.main.bundleIdentifier!

    /// Logs WebAuthn operations.
    static let webauthn = OSLog(subsystem: subsystem, category: "webauthn")
    
    /// Logs CryptoKit and SecKey type operations.
    static let crypto = OSLog(subsystem: subsystem, category: "crypto")
}

// MARK: CryptoKit Extensions

/// :nodoc:
/// A mechanism used to create a shared secret between two users by performing X25519 key agreement.
extension Curve25519.KeyAgreement.PrivateKey: @retroactive CustomStringConvertible {}
extension Curve25519.KeyAgreement.PrivateKey: SecKeyConvertible {}

/// :nodoc:
/// A mechanism used to create or verify a cryptographic signature using Ed25519.
extension Curve25519.Signing.PrivateKey: @retroactive CustomStringConvertible {}
extension Curve25519.Signing.PrivateKey: SecKeyConvertible {}

/// Ensure that SymmetricKey is generic password convertible.
extension SymmetricKey: @retroactive CustomStringConvertible {}
extension SymmetricKey: SecKeyConvertible {
    /// Creates a new ``SymmetricKey`` object.
    /// - Parameter data: Contiguous bytes repackaged as a Data instance.
    init<D>(rawRepresentation data: D) throws where D: ContiguousBytes {
        self.init(data: data)
    }
    
    /// Contiguous bytes repackaged as a Data instance.
    var rawRepresentation: Data {
        return dataRepresentation
    }
}

/// :nodoc:
/// Ensure that Secure Enclave keys are generic password convertible.
extension SecureEnclave.P256.KeyAgreement.PrivateKey: @retroactive CustomStringConvertible {}
extension SecureEnclave.P256.KeyAgreement.PrivateKey: SecKeyConvertible {
    /// Creates a private key  from a data representation of the key.
    /// - Parameter rawRepresentation: Contiguous bytes repackaged as a Data instance.
    init<D>(rawRepresentation data: D) throws where D: ContiguousBytes {
        try self.init(dataRepresentation: data.dataRepresentation)
    }
    
    /// Contiguous bytes repackaged as a Data instance.
    var rawRepresentation: Data {
        return dataRepresentation  // Contiguous bytes repackaged as a Data instance.
    }
}

/// :nodoc:
/// A representation of a device’s hardware-based key manager.
extension SecureEnclave.P256.Signing.PrivateKey: @retroactive CustomStringConvertible {}
extension SecureEnclave.P256.Signing.PrivateKey: SecKeyConvertible {
    /// Creates a private key  from a data representation of the key.
    /// - Parameter rawRepresentation: Contiguous bytes repackaged as a Data instance.
    init<D>(rawRepresentation data: D) throws where D: ContiguousBytes {
        try self.init(dataRepresentation: data.dataRepresentation)
    }
    
    /// Contiguous bytes repackaged as a Data instance.
    var rawRepresentation: Data {
        return dataRepresentation 
    }
}

/// Indicates that the conforming type is a contiguous collection of raw bytes whose underlying storage is directly accessible by withUnsafeBytes.
extension ContiguousBytes {
    /// A Data instance created safely from the contiguous bytes without making any copies.
    var dataRepresentation: Data {
        return self.withUnsafeBytes { bytes in
            guard let cfdata = CFDataCreateWithBytesNoCopy(nil, bytes.baseAddress?.assumingMemoryBound(to: UInt8.self), bytes.count, kCFAllocatorNull) else {
                return Data()
            }
            return cfdata as Data
        }
    }
}
