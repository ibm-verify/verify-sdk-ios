//
// Copyright contributors to the IBM Verify Core SDK for iOS project
//

import Foundation
import Security
import OSLog
import LocalAuthentication

// MARK: Enum

/// An error that occurs during keychain operations.
public enum KeychainError: Error, Equatable {
    /// The name of the key is empty or is considered invalid.
    case invalidKey
    
    /// A key with the same name already exists.
    case duplicateKey
    
    /// Unexpected data was being written to or read from the keychain.
    case unexpectedData
    
    /// An unhandled error occurred perform the keychain operation.
    case unhandledError(message: String)
}

/// Access control constants that dictate how a keychain item may be used.
public enum SecAccessControl: RawRepresentable {
    public typealias RawValue = SecAccessControlCreateFlags
    
    /// Constraint to access an item with a passcode.
    case devicePasscode
    
    /// Constraint to access an item with Touch ID for any enrolled fingers, or Face ID.
    ///
    /// The app's Info.plist must contain an `NSFaceIDUsageDescription` key with a string value explaining to the user how the app uses this data.
    case biometryAny
    
    /// Constraint to access an item with Touch ID for currently enrolled fingers, or from Face ID with the currently enrolled user.
    ///
    /// The app's Info.plist must contain an `NSFaceIDUsageDescription` key with a string value explaining to the user how the app uses this data.
    case biometryCurrentSet
    
    /// Constraint to access an item with either biometry or passcode.
    ///
    /// The app's Info.plist must contain an `NSFaceIDUsageDescription` key with a string value explaining to the user how the app uses this data.
    case userPresence
    
    /// Creates a new instance with the specified raw value.
    ///
    /// If there is no value of the type that corresponds with the specified raw
    /// value, this initializer returns `nil`. For example:
    ///
    /// - Parameter rawValue: The raw value to use for the new instance.
    public init?(rawValue: SecAccessControlCreateFlags) {
        switch rawValue {
        case SecAccessControlCreateFlags.devicePasscode:
            self = .devicePasscode
        case SecAccessControlCreateFlags.biometryAny:
            self = .biometryAny
        case SecAccessControlCreateFlags.biometryCurrentSet:
            self = .biometryCurrentSet
        case SecAccessControlCreateFlags.userPresence:
            self = .userPresence
        default:
            return nil
        }
    }
    
    public var rawValue: RawValue {
        switch self {
        case .devicePasscode:
            return SecAccessControlCreateFlags.devicePasscode
        case .biometryAny:
            return SecAccessControlCreateFlags.biometryAny
        case .biometryCurrentSet:
            return SecAccessControlCreateFlags.biometryCurrentSet
        case .userPresence:
            return SecAccessControlCreateFlags.userPresence
        }
    }
}

/// Set the conditions under which an app can access a keychain item.
public enum SecAccessible: RawRepresentable {
    public typealias RawValue = CFString
    
    /// The data in the keychain item can be accessed only while the device is unlocked by the user.
    case whenUnlockedThisDeviceOnly
    
    /// The data in the keychain item can be accessed only while the device is unlocked by the user.
    case whenUnlocked
    
    /// The data in the keychain item cannot be accessed after a restart until the device has been unlocked once by the user.
    case afterFirstUnlockThisDeviceOnly
    
    /// The data in the keychain item cannot be accessed after a restart until the device has been unlocked once by the user.
    case afterFirstUnlock
    
    /// Creates a new instance with the specified raw value.
    ///
    /// If there is no value of the type that corresponds with the specified raw
    /// value, this initializer returns `nil`. For example:
    ///
    /// - Parameter rawValue: The raw value to use for the new instance.
    public init?(rawValue: CFString) {
        switch rawValue {
        case kSecAttrAccessibleWhenUnlockedThisDeviceOnly:
            self = .whenUnlockedThisDeviceOnly
        case kSecAttrAccessibleWhenUnlocked:
            self = .whenUnlocked
        case kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly:
            self = .afterFirstUnlockThisDeviceOnly
        case kSecAttrAccessibleAfterFirstUnlock:
            self = .afterFirstUnlock
        default:
            return nil
        }
    }
    
    public var rawValue: RawValue {
        switch self {
        case .whenUnlockedThisDeviceOnly:
            return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case .whenUnlocked:
            return kSecAttrAccessibleWhenUnlocked
        case .afterFirstUnlockThisDeviceOnly:
            return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        case .afterFirstUnlock:
            return kSecAttrAccessibleAfterFirstUnlock
        }
    }
}

/// The keychain is the best place to store small secrets, like passwords and cryptographic keys. Use the functions of the keychain services API to add, retrieve, delete, or modify keychain items.
/// - Note: The keychain service is specific to the IBM Verify in that, the keychain is not synchronized with Apple iCloud and access to the items in the keychain occurs after the first device unlock operation.
public final class KeychainService: NSObject {
    // MARK: Variables
    private let logger: Logger
    private let serviceName = Bundle.main.bundleIdentifier!
    
    private static let _default = KeychainService()
    
    /// Returns the default singleton instance.
    public class var `default`: KeychainService {
        get {
            return _default
        }
    }
    
    /// Initializes the `KeychainService`.
    public override init() {
        logger = Logger(subsystem: serviceName, category: "keychain")
    }
    
    // MARK: Keychain methods
    
    /// Adds an item to a keychain.
    /// - Parameters:
    ///   - forKey: The key with which to associate the value.
    ///   - value: The value to store in the keychain.
    ///   - accessControl: One or more flags that determine how the value can be accessed. See [SecAccessControlCreateFlags](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags).
    ///   - accessibility: A key whose value indicates when a keychain item is accessible. Default is `SecAccessible.afterFirstUnlock`.
    ///
    /// ```swift
    /// struct Person: Codable {
    ///    var name: String
    ///    var age: Int
    /// }
    ///
    /// let person = Person(name: "John Doe", age: 42)
    /// try? KeychainService.default.addItem("account", value: person)
    /// ```
    public func addItem<T: Codable>(_ forKey: String, value: T, accessControl: SecAccessControl? = nil, accessibility: SecAccessible = .afterFirstUnlock) throws {
        guard let data = try? JSONEncoder().encode(value) else {
            throw KeychainError.unexpectedData
        }
        
        try addItem(forKey, value: .generic(value: data), accessControl: accessControl, accessibility: accessibility)
    }
    
    /// Adds an item to a keychain, or updates a value if the key already exists.
    ///
    /// This function securely stores a key or generic data in the Keychain. It supports synchronizing across devices and applies specified access controls.
    ///
    /// - Parameters:
    ///   - forKey: The key with which to associate the value.
    ///   - value: The keychain item type, either a generic password (`.generic`) or a cryptographic key (`.key`).
    ///   - allowSync: A Boolean flag indicating whether the item should be synchronized across devices using iCloud Keychain. Defaults to `false`.
    ///   - accessControl: Optional `SecAccessControl` specifying security attributes such as biometrics or device passcode restrictions. See [SecAccessControlCreateFlags](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags).
    ///   - accessibility: Defines when the item is accessible (e.g., after first unlock). Defaults to `SecAccessible.afterFirstUnlock`.
    /// - Throws: `KeychainError` if the operation fails.
    ///
    /// ```swift
    /// let key = RSA.Signing.PrivateKey(keySize: .bits2048)
    /// let info = SecKeyAddType.key(value: key.derRepresentation, size: 2048, algorithm: .RSA)
    ///
    /// try? KeychainService.default.addItem("private-key", value: info, allowSync: true)
    /// ```
    public func addItem(_ forKey: String, value: SecKeyAddType, allowSync: Bool = false, accessControl: SecAccessControl? = nil, accessibility: SecAccessible = .afterFirstUnlock) throws {
        guard !forKey.isEmpty else {
            logger.error("The forKey argument is invalid.")
            throw KeychainError.invalidKey
        }
        
        var query: [String: Any] = [:]
        
        // Prepare the query to be written to the keychain.
        switch value {
        case .generic(let data):
            query = [kSecClass as String: kSecClassGenericPassword,
                     kSecAttrAccount as String: forKey,
                     kSecAttrService as String: serviceName,
                     kSecValueData as String: data]
        case .key(let data, let size, let algorithm):
            query = [kSecClass as String: kSecClassKey,
                     kSecAttrKeySizeInBits as String: size,
                     kSecAttrKeyType as String: algorithm.rawValue,
                     kSecAttrApplicationTag as String: Data(forKey.utf8),
                     kSecAttrIsPermanent as String: true,
                     kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                     kSecValueData as String: data]
        }
        
        let values: [String: Any] = [kSecAttrSynchronizable as String: allowSync]
        
        // Check if any access control is to be applied. Otherwise apply just the accessible item.
        if let accessControl = accessControl {
            var error: Unmanaged<CFError>?
            
            guard let accessControlFlags = SecAccessControlCreateWithFlags(kCFAllocatorDefault, accessibility.rawValue, accessControl.rawValue, &error) else {
                let message = error?.takeRetainedValue().localizedDescription ?? "Unknown access control error."
                logger.error("Error occurred applying access control. \(message, privacy: .public)")
                
                throw KeychainError.unhandledError(message: message)
            }
            
            query[kSecAttrAccessControl as String] = accessControlFlags
        }
        else {
            query[kSecAttrAccessible as String] = accessibility.rawValue
        }

        let params = query.merging(values) { $1 }
        var status = SecItemAdd(params as CFDictionary, nil)
        
        switch status {
        case errSecSuccess:
            logger.info("Item '\(forKey, privacy: .public)' added to keychain: \(status == errSecSuccess, privacy: .public)")
        case errSecDuplicateItem:
            status = SecItemUpdate(query as CFDictionary, values as CFDictionary)
            logger.info("Item '\(forKey, privacy: .public)' updated in keychain: \(status == errSecSuccess, privacy: .public)")
        default:
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "Unknown error"
            logger.error("Error occured performing the operation. \(message, privacy: .public)")
            throw KeychainError.unhandledError(message: message)
        }
    }
    
    /// Delete an item from the keychain.
    ///
    /// - Parameters:
    ///   - forKey: The key with which to associate the value.
    ///   - searchType: The keychain search type, either a generic password (`.generic`) or a cryptographic key (`.key`).
    /// - Throws: `KeychainError` if an error occurs.
    ///
    /// ```swift
    /// try? KeychainService.default.deleteItem("account", searchType: .generic)
    /// ```
    /// - Remark: No error is thrown when the key is not found.
    public func deleteItem(_ forKey: String, searchType: SecKeySearchType = .generic) throws {
        guard !forKey.isEmpty else {
            logger.error("The forKey argument is invalid.")
            throw KeychainError.invalidKey
        }
        
        var query: [String: Any] = [:]
        
        // Construct the query to search for the 'forKey' within different kSecClass types.
        switch searchType {
        case .generic:
            query[kSecClass as String] = kSecClassGenericPassword
            query[kSecAttrAccount as String] = forKey
            query[kSecAttrService as String] = serviceName
        case .key:
            query[kSecClass as String] = kSecClassKey
            query[kSecAttrApplicationTag as String] = Data(forKey.utf8)
            query[kSecAttrKeyClass as String] = kSecAttrKeyClassPrivate
        }
            
        let status = SecItemDelete(query as CFDictionary)
        
        // Check the status for an error.
        switch status {
        case errSecSuccess:
            logger.info("Item '\(forKey, privacy: .public)' was deleted from Keychain.")
            return
        case errSecItemNotFound:
            logger.info("'\(forKey, privacy: .public)' not found in Keychain. Status: \(status, privacy: .public)")
            return
        default:
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "Unknown error"
            logger.error("Error occured performing the operation. \(message, privacy: .public). Status: \(status, privacy: .public)")
            throw KeychainError.unhandledError(message: message)
        }
    }
    
    /// Reads an item from the Keychain and decodes it into the specified type.
    ///
    /// This function retrieves stored data from the Keychain based on the provided key and search type.
    /// The retrieved data is then decoded into the desired Codable type.
    ///
    /// - Parameters:
    ///   - forKey: The unique identifier for the stored item.
    ///   - searchType: The Keychain search type (`.generic` for passwords or `.key` for cryptographic keys).
    ///   - type: The type of object that the stored data should be decoded into.
    /// - Throws: `KeychainError` if the item cannot be found or decoding fails.
    /// - Returns: The retrieved and decoded object of type `T`, if found.
    ///
    /// ```swift
    /// struct Person {
    ///    var name: String
    ///    var age: Int
    /// }
    ///
    /// guard let person = try? KeychainService.default.readItem("account", searchType: .generic, type: Person.self) else {
    ///    return
    /// }
    ///
    /// print(person)
    /// ```
    public func readItem<T: Codable>(_ forKey: String, searchType: SecKeySearchType = .generic, type: T.Type) throws -> T {
        let data = try readItem(forKey, searchType: searchType)
        
        // Attempt to decode the value back to it's type.
        let result = try JSONDecoder().decode(T.self, from: data)
        
        return result
    }
    
    /// Reads a `Data` from the keychain.
    /// - Parameters:
    ///   - forKey: The key with which to associate the value.
    /// - Returns: The data value.
    ///
    /// ```swift
    /// let value = "Hello world".data(using: .utf8)!
    /// try KeychainService.default.addItem("greeting", value: value)
    /// let result = try KeychainService.default.readItem("greeting")
    ///
    /// print(String(data: result, encoding: .utf8))
    /// ```
    public func readItem(_ forKey: String, searchType: SecKeySearchType = .generic) throws -> Data {
        guard !forKey.isEmpty else {
            logger.error("The forKey argument is invalid.")
            throw KeychainError.invalidKey
        }
        
        var query: [String: Any] = [
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnData as String: true]
        
        // Configure query based on item type
        switch searchType {
        case .generic:
            query[kSecClass as String] = kSecClassGenericPassword
            query[kSecAttrAccount as String] = forKey
            query[kSecAttrService as String] = serviceName

        case .key:
            query[kSecClass as String] = kSecClassKey
            query[kSecAttrApplicationTag as String] = Data(forKey.utf8)
            query[kSecAttrKeyClass as String] = kSecAttrKeyClassPrivate
        }
        
        // Perform Keychain lookup.
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
            
        // Handle lookup results
        let message = SecCopyErrorMessageString(status, nil) as String? ?? "Unknown error"
        
        // Check the status for an error.
        switch status {
        case errSecSuccess:
            // Attempt to decode the value back to it's type.
            guard let result = item as? Data else {
                logger.warning("Invalid data associated with key '\(forKey, privacy: .public)'")
                throw KeychainError.unexpectedData
            }

            return result
        case errSecUserCanceled:
            logger.warning("The user cancelled the operation. Status: \(status, privacy: .public)")
            throw KeychainError.unhandledError(message: message)
        case errSecItemNotFound, errSecInvalidItemRef:
            logger.warning("The specified item not found in Keychain. Status: \(status, privacy: .public)")
            throw KeychainError.invalidKey
        default:
            logger.warning("An error occured accessing the Keychain. Status: \(status, privacy: .public)")
            throw KeychainError.unhandledError(message: message)
        }
    }
    
    /// Query the keychain for a matching key.
    /// - Parameters:
    ///   - forKey: The key with which to associate the value.
    ///   - searchType: The keychain search type, either a generic password (`.generic`) or a cryptographic key (`.key`).
    /// - Returns:`true` if the key exists, otherwise `false`.
    ///
    /// If the key has been generated requiring authentication for access, the UI has been surpressed.  Therefore the function will return `true` under the following conditions:
    /// - `errSecSuccess` The item was found, no error.
    /// - `errSecInteractionNotAllowed` The item was found, the user interaction is not allowed.
    /// - `errSecAuthFailed` The item was found, but invalidated due to a change to biometry or passphrase.
    ///
    /// ```swift
    /// let result = KeychainService.default.itemExists("greeting", searchType: .key)
    /// print(result)
    /// ```
    public func itemExists(_ forKey: String, searchType: SecKeySearchType = .generic) -> Bool {
        // Construct a LAContext to surpress any biometry to access the key.
        let context = LAContext()
        context.interactionNotAllowed = true
      
        // Define the base query for Keychain search.
        var query: [String: Any] = [
            kSecMatchLimit as String: kSecMatchLimitOne,    // Return only one matching item
            kSecReturnData as String: false]                // We only need existence check, not actual data

        // Adjust query based on item type
        switch searchType {
        case .generic:
            query[kSecClass as String] = kSecClassGenericPassword
            query[kSecAttrService as String] = serviceName
            query[kSecAttrAccount as String] = forKey
            query[kSecUseAuthenticationContext as String] = context

        case .key:
            query[kSecClass as String] = kSecClassKey
            query[kSecAttrKeyClass as String] = kSecAttrKeyClassPrivate
            query[kSecAttrApplicationTag as String] = Data(forKey.utf8)
        }

        // Perform Keychain lookup
        let status = SecItemCopyMatching(query as CFDictionary,nil)
        
        logger.info("Item '\(forKey, privacy: .public)' exists in Keychain: \(status == errSecSuccess || status == errSecInteractionNotAllowed || status == errSecAuthFailed, privacy: .public)")

        switch status {
        case errSecSuccess, errSecInteractionNotAllowed, errSecAuthFailed:
            return true  // Item exists
        default:
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "Unknown keychain error"
            logger.error("Keychain existence check error: \(message)")
            return false  // Error occured
        }
    }
    
    /// Evaluates if the `LocalAuthentication` policy has changed from an initial domain state.
    /// - Parameter evaluatedPolicyDomainState: The initial policy domain state.  Default value is `nil`.
    /// - Returns: `true` if the current domain state has changed, otherwise `false`.
    ///
    /// ```swift
    /// if let initialDomainStateData = LAContext().evaluatedPolicyDomainState {
    ///    // Persist the initialDomainStateData for future use.
    /// }
    /// ...
    ///
    /// // Get the initialDomainStateData from persistence, check to see if it has changed against the current domain state.
    /// if KeychainService.default.hasAuthenticationSettingsChanged(initialDomainStateData) {
    ///    print("User has changed their biometry enrollment.")
    /// }
    /// ```
    public func hasPolicyDomainStateChanged(_ evaluatedPolicyDomainState: Data? = nil) -> Bool {
        // If biometry is not available, then the keys haven't changed.
        let context = LAContext()
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) else {
            return false
        }

        // If a new fingerprint has been enrolled, this will change the current evaluated domain state.
        guard let domainState = context.evaluatedPolicyDomainState, domainState == evaluatedPolicyDomainState else {
            return true
        }

        return false
    }
    
    /// Renames a Keychain item by updating its unique identifier.
    ///
    /// This function searches for an existing item and updates its associated key.
    /// It can be used to rename both **generic** and **keys** stored in the Keychain.
    ///
    /// - Parameters:
    ///   - forKey: The existing unique identifier of the Keychain item.
    ///   - newKey: The new identifier to replace the old one.
    ///   - searchType: The type of Keychain item (`generic` or `key`).
    /// - Throws: `KeychainError` if renaming fails.
    ///
    /// ```swift
    /// do {
    ///    try KeychainHelper.default.rename("oldKey", newKey: "newKey", searchType: .generic)
    /// }
    /// catch let error {
    ///    print(error.localizedDescription)
    /// }
    /// ```
    public func renameItem(_ forKey: String, newKey: String, searchType: SecKeySearchType = .generic) throws {
        // Construct a LAContext to surpress any biometry to access the key.
        let context = LAContext()
        context.interactionNotAllowed = true
        
        var query: [String: Any] = [:]
        var updateAttributes: [String: Any] = [:]

        // Configure query based on item type
        switch searchType {
        case .generic:
            query[kSecClass as String] = kSecClassGenericPassword
            query[kSecAttrService as String] = serviceName
            query[kSecAttrAccount as String] = forKey
            query[kSecUseAuthenticationContext as String] = context
            updateAttributes[kSecAttrLabel as String] = newKey

        case .key:
            query[kSecClass as String] = kSecClassKey
            query[kSecAttrApplicationTag as String] = Data(forKey.utf8)
            query[kSecAttrKeyClass as String] = kSecAttrKeyClassPrivate
            updateAttributes[kSecAttrApplicationTag as String] = Data(newKey.utf8)
        }
            
        // Attempt to update the item
        let status = SecItemUpdate(query as CFDictionary, updateAttributes as CFDictionary)
        
        logger.info("Rename key from '\(forKey, privacy: .public)' to '\(newKey, privacy: .public)': \(status == errSecSuccess, privacy: .public)")
      
        switch status {
        case errSecSuccess:
            return
        default:
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "Unknown error"
            logger.error("Error occured performing the operation. \(message, privacy: .public)")
            throw KeychainError.unhandledError(message: message)
        }
    }
}


/// Represent the cryptographic algorithm of the key being stored.
public enum SecAlgorithmType: RawRepresentable {
    public typealias RawValue = CFString
    
    /// RSA algorithm.
    case RSA
    
    /// Elliptic curve algorithm.
    case ECSECPrimeRandom
    
    /// Creates a new instance with the specified raw value.
    ///
    /// If there is no value of the type that corresponds with the specified raw
    /// value, this initializer returns `nil`. For example:
    ///
    /// - Parameter rawValue: The raw value to use for the new instance.
    public init?(rawValue: CFString) {
        switch rawValue {
        case kSecAttrKeyTypeRSA:
            self = .RSA
        case kSecAttrKeyTypeECSECPrimeRandom:
            self = .ECSECPrimeRandom
        default:
            return nil
        }
    }
    
    public var rawValue: RawValue {
        switch self {
        case .RSA:
            return kSecAttrKeyTypeRSA
        case .ECSECPrimeRandom:
            return kSecAttrKeyTypeECSECPrimeRandom
        }
    }
}

/// Represents the supported types of `kSecClass` items that can be added to the Keychain.
public enum SecKeyAddType {
    /// Stores a generic data value in the Keychain.
    /// - Parameter value: The raw `Data` to be stored.
    case generic(value: Data)
    
    /// Stores a cryptographic key in the Keychain with specific attributes.
    /// - Parameter value: The raw `Data` representation of the key.
    /// - Parameter size: The key size in bits (e.g., 256 for an AES key).
    /// - Parameter algorithm: The cryptographic algorithm associated with the key (e.g., RSA, ECSECPrimeRandom).
    case key(value: Data, size: Int = 2048, algorithm: SecAlgorithmType = .RSA)
}

/// Represents the supported types of `kSecClass` that can be searched in the Keychain.
public enum SecKeySearchType {
    /// Searches for a `kSecClassGenericPassword` item in the Keychain.
    case generic
    
    /// Searches for a `kSecClassKey` private key item in the Keychain.
    case key
}
