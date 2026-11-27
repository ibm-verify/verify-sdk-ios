//
// Copyright contributors to the IBM Verify FIDO2 SDK for iOS project
//

import Foundation
import Security
import LocalAuthentication
import CryptoKit
import os.log

/// A Secure Enclave backed private key that can be used to produce WebAuthn signatures, independent of the underlying algorithm.
public protocol SecureEnclaveSigningKey {
    /// The COSE algorithm the key is used with.
    var algorithm: COSEAlgorithmIdentifier { get }
    
    /// The opaque, Secure Enclave key reference used to persist and later restore the key.
    var dataRepresentation: Data { get }
    
    /// The public key bytes used to derive the credential identifier.
    var publicKeyData: Data { get }
    
    /// The public key encoded as a `COSE_Key`.
    var cosePublicKey: [UInt8] { get }
    
    /// Signs the data using the format expected by WebAuthn relying parties.
    /// - Parameter data: The data to sign.
    /// - Returns: A DER encoded ECDSA signature for ES256, otherwise the raw ML-DSA signature.
    func sign(_ data: Data) throws -> Data
}

extension SecureEnclave.P256.Signing.PrivateKey: SecureEnclaveSigningKey {
    public var algorithm: COSEAlgorithmIdentifier { .es256 }
    
    public var publicKeyData: Data { publicKey.derRepresentation }
    
    public var cosePublicKey: [UInt8] {
        // The x9.63 representation is 0x04 || X (32 bytes) || Y (32 bytes).
        let point = [UInt8](publicKey.x963Representation)
        return COSEKeyEC2(alg: COSEAlgorithmIdentifier.es256.rawValue,
                          crv: COSEKeyCurveType.p256,
                          xCoord: Array(point[1..<33]),
                          yCoord: Array(point[33..<65])).bytes
    }
    
    public func sign(_ data: Data) throws -> Data {
        return try signature(for: data).derRepresentation
    }
}

@available(iOS 26.0, macCatalyst 26.0, *)
extension SecureEnclave.MLDSA65.PrivateKey: SecureEnclaveSigningKey {
    public var algorithm: COSEAlgorithmIdentifier { .mldsa65 }
    
    public var publicKeyData: Data { publicKey.rawRepresentation }
    
    public var cosePublicKey: [UInt8] {
        return COSEKeyAKP(alg: COSEAlgorithmIdentifier.mldsa65.rawValue, pub: [UInt8](publicKey.rawRepresentation)).bytes
    }
    
    public func sign(_ data: Data) throws -> Data {
        return try signature(for: data)
    }
}

@available(iOS 26.0, macCatalyst 26.0, *)
extension SecureEnclave.MLDSA87.PrivateKey: SecureEnclaveSigningKey {
    public var algorithm: COSEAlgorithmIdentifier { .mldsa87 }
    
    public var publicKeyData: Data { publicKey.rawRepresentation }
    
    public var cosePublicKey: [UInt8] {
        return COSEKeyAKP(alg: COSEAlgorithmIdentifier.mldsa87.rawValue, pub: [UInt8](publicKey.rawRepresentation)).bytes
    }
    
    public func sign(_ data: Data) throws -> Data {
        return try signature(for: data)
    }
}

/// This class provides helper methods to generate, query and delete private keys.  In addition, the class provides the ability to sign data and export the public key.
///
/// The key algorithm is selectable when generating a key. ES256 (P-256) is the default, with ML-DSA-65 and ML-DSA-87 available on iOS 26 and Mac Catalyst 26 and later. The algorithm is persisted alongside the key, so keys are restored with the algorithm they were created with.
internal struct SecKeyStore {
    private let serviceName: String
    private let accessGroup: String?
    
    // The access control to geneate and sign with the private key.
    private let accessControl = SecAccessControlCreateWithFlags(nil,
                                                                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                                [.privateKeyUsage, .userPresence],
                                                                nil)!
    
    /// Initializes the KeyStore with identifying tags and groups.
    /// - Parameters:
    ///   - applicationTag: A unique string identifying this category of keys.
    ///   - accessGroup: The shared Keychain Group (e.g. "TEAMID.group.com.app"). If nil, uses private keychain.
    init(serviceName: String, accessGroup: String? = nil) {
        // Convert to Data immediately as the Keychain API requires [kSecAttrApplicationTag: Data]
        self.serviceName = serviceName
        self.accessGroup = accessGroup
    }
    
    // MARK: - Helper Methods
        
    /// Constructs the base query used for identifying keys in the keychain.
    internal func query(for account: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: account
        ]
        
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        
        return query
    }
    
    /// Indicates whether keys of the algorithm can be generated on this device.
    /// - Parameter algorithm: The algorithm to check.
    internal static func isSupported(_ algorithm: COSEAlgorithmIdentifier) -> Bool {
        switch algorithm {
        case .es256:
            return true
        case .mldsa65, .mldsa87:
            if #available(iOS 26.0, macCatalyst 26.0, *) {
                return true
            }
            return false
        default:
            return false
        }
    }
    
    /// Selects the algorithm for a new key from the relying party's ordered list of preferences.
    /// - Parameter parameters: The `pubKeyCredParams` of the registration options, most preferred first.
    /// - Returns: The first supported algorithm. When the list is empty, `es256` is returned as the WebAuthn default. Returns `nil` when the list has no supported algorithm.
    internal static func selectAlgorithm(from parameters: [PublicKeyCredentialParameters]) -> COSEAlgorithmIdentifier? {
        guard !parameters.isEmpty else {
            return .es256
        }
        
        return parameters
            .compactMap { $0.alg }
            .first { isSupported($0) }
    }
    
    /// Encodes the algorithm so it can be persisted with the key in the keychain.
    internal static func encode(_ algorithm: COSEAlgorithmIdentifier) -> Data {
        return Data(String(algorithm.rawValue).utf8)
    }
    
    /// Decodes the algorithm persisted with a key in the keychain.
    /// - Parameter data: The persisted value. Keys stored before the algorithm was persisted have no value and are ES256.
    internal static func decode(_ data: Data?) -> COSEAlgorithmIdentifier? {
        guard let data = data else {
            return .es256
        }
        
        guard let value = String(data: data, encoding: .utf8), let rawValue = Int(value) else {
            return nil
        }
        
        return COSEAlgorithmIdentifier.parse(from: rawValue)
    }
    
    /// Creates a new Secure Enclave key for the algorithm.
    private func createKey(_ algorithm: COSEAlgorithmIdentifier, context: LAContext) throws -> any SecureEnclaveSigningKey {
        switch algorithm {
        case .es256:
            return try SecureEnclave.P256.Signing.PrivateKey(compactRepresentable: true,
                                                             accessControl: self.accessControl,
                                                             authenticationContext: context)
        case .mldsa65:
            guard #available(iOS 26.0, macCatalyst 26.0, *) else {
                throw KeyStoreError("Algorithm \(algorithm) requires iOS 26.0 or Mac Catalyst 26.0 or later.")
            }
            return try SecureEnclave.MLDSA65.PrivateKey(accessControl: self.accessControl, authenticationContext: context)
        case .mldsa87:
            guard #available(iOS 26.0, macCatalyst 26.0, *) else {
                throw KeyStoreError("Algorithm \(algorithm) requires iOS 26.0 or Mac Catalyst 26.0 or later.")
            }
            return try SecureEnclave.MLDSA87.PrivateKey(accessControl: self.accessControl, authenticationContext: context)
        default:
            throw KeyStoreError("Algorithm \(algorithm) is not supported.")
        }
    }
    
    /// Restores a Secure Enclave key from its data representation.
    private func restoreKey(_ algorithm: COSEAlgorithmIdentifier, data: Data, context: LAContext) throws -> any SecureEnclaveSigningKey {
        switch algorithm {
        case .es256:
            return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data, authenticationContext: context)
        case .mldsa65:
            guard #available(iOS 26.0, macCatalyst 26.0, *) else {
                throw KeyStoreError("Algorithm \(algorithm) requires iOS 26.0 or Mac Catalyst 26.0 or later.")
            }
            return try SecureEnclave.MLDSA65.PrivateKey(dataRepresentation: data, authenticationContext: context)
        case .mldsa87:
            guard #available(iOS 26.0, macCatalyst 26.0, *) else {
                throw KeyStoreError("Algorithm \(algorithm) requires iOS 26.0 or Mac Catalyst 26.0 or later.")
            }
            return try SecureEnclave.MLDSA87.PrivateKey(dataRepresentation: data, authenticationContext: context)
        default:
            throw KeyStoreError("Algorithm \(algorithm) is not supported.")
        }
    }
    
    // MARK: - Key Operations

    /// Generates the private and public key for future signing operations.
    /// - Parameters:
    ///   - algorithm: The algorithm of the key. Supported values are `es256` (default), `mldsa65` and `mldsa87`.
    ///   - context: The Local Authentication context to associate with the key.
    func generate(algorithm: COSEAlgorithmIdentifier = .es256, context: LAContext) throws -> any SecureEnclaveSigningKey {
        os_log("Generating %{public}@ private key in SecureEnclave.", log: .crypto, type: .info, String(describing: algorithm))
        
        // Note: The key in memory first. The 'add' method will persist the reference.
        let key = try createKey(algorithm, context: context)
        os_log("Private key created successfully.", log: .crypto, type: .info)
        return key
    }
    
    /// Stores a SecureEnclave key reference, and its algorithm, in the keychain.
    /// - Parameters:
    ///   - account: The account to store the key under (usually the Credential ID).
    ///   - key: The key generated by the Secure Enclave.
    func add(_ account: String, key: any SecureEnclaveSigningKey) throws {
        var query = query(for: account)
        
        // Add the data
        query[kSecValueData as String] = key.dataRepresentation // Store the opaque reference
        query[kSecAttrGeneric as String] = SecKeyStore.encode(key.algorithm)
        
        let status = SecItemAdd(query as CFDictionary, nil)
        
        guard status == errSecSuccess else {
            os_log("Unable to store item %{public}@. Status: %{public}@", log: .default, type: .error, account, status.message)
            throw KeyStoreError("Unable to store item. \(status.message)")
        }
        
        os_log("Key %{public}@ added to Keychain.", log: .crypto, type: .info, account)
    }
    
    /// Reads a SecureEnclave key from the keychain.
    /// - Parameters:
    ///   - account: The account assigned to the key.
    ///   - context: The Local Authentication context to associate with the key.
    /// - Returns: The key, restored using the algorithm it was stored with, if found, otherwise `nil`.
    func read(_ account: String, context: LAContext) -> (any SecureEnclaveSigningKey)? {
        var query = query(for: account)
        query[kSecReturnData as String] = true
        query[kSecReturnAttributes as String] = true
        
        // Find and cast the result as attributes containing the data.
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        switch status {
        case errSecSuccess:
            guard let attributes = item as? [String: Any], let data = attributes[kSecValueData as String] as? Data else {
                return nil
            }
            
            guard let algorithm = SecKeyStore.decode(attributes[kSecAttrGeneric as String] as? Data) else {
                os_log("Key %{public}@ has an unrecognized algorithm.", log: .crypto, type: .error, account)
                return nil
            }
            
            os_log("Key found with name %{public}@.", log: .crypto, type: .info, account)
            // Reconstruct the key from the reference data
            return try? restoreKey(algorithm, data: data, context: context)
            
        case errSecItemNotFound:
            os_log("No key found with name %{public}@.", log: .crypto, type: .info, account)
            return nil
            
        default:
            os_log("Keychain read failed for %{public}@. Status: %{public}@", log: .crypto, type: .error, account, status.message)
            return nil
        }
    }
    
    /// Removes any existing key with the given account.
    /// - Parameter account: The account assigned to the key.
    func delete(_ account: String) throws {
        let query = query(for: account)
        
        let status = SecItemDelete(query as CFDictionary)
        
        switch status {
        case errSecItemNotFound, errSecSuccess:
            os_log("Key %{public}@ deleted (or did not exist).", log: .crypto, type: .info, account)
            break // Okay to ignore
        default:
            os_log("Unexpected deletion error for %{public}@. Status: %{public}@", log: .crypto, type: .error, account, status.message)
            throw KeyStoreError("Unexpected deletion error. \(status.message)")
        }
    }
}

/// The error description for a failed `SecKey` operations.
struct KeyStoreError: Error, LocalizedError, CustomStringConvertible {
    private var _description: String
    
    /// Initiatizes a new `KeyStoreError` instance.
    /// - Parameter description: The error messge accompanying the error.
    init(_ description: String) {
        self._description = description
    }
    
    /// The error description accompanying the error.
    public var description: String {
        return _description
    }
    
    public var localizedDescription: String {
        return NSLocalizedString(_description, comment: "")
    }
}

extension OSStatus {
    /// A human readable message for the status.
    var message: String {
        return (SecCopyErrorMessageString(self, nil) as String?) ?? String(self)
    }
}
