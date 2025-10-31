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
        
        try addItem(forKey, value: data, accessControl: accessControl, accessibility: accessibility)
    }
    
    /// Adds an item to a keychain, or updates a value if the key already exists.
    /// - Parameters:
    ///   - forKey: The key with which to associate the value.
    ///   - value: The `Data` value to store in the keychain.
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
    public func addItem(_ forKey: String, value: Data, accessControl: SecAccessControl? = nil, accessibility: SecAccessible = .afterFirstUnlock) throws {
        guard !forKey.isEmpty else {
            logger.error("The forKey argument is invalid.")
            throw KeychainError.invalidKey
        }
        
        // Prepare the query to be writtern to the keychain.
        var query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: serviceName,
                                    kSecAttrAccount as String: forKey]
        
        
        let values: [String: Any] = [kSecValueData as String: value]
        
    
        // Check if any access control is to be applied. Otherwise apply just the accessible item.
        if let accessControl = accessControl {
            var error: Unmanaged<CFError>?
            
            guard let accessControlFlags = SecAccessControlCreateWithFlags(kCFAllocatorDefault, accessibility.rawValue, accessControl.rawValue, &error) else {
                let message = error!.takeRetainedValue().localizedDescription
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
    /// - Parameter forKey: The key with which to associate the value.
    ///
    /// ```swift
    /// try? KeychainService.default.deleteItem("account")
    /// ```
    /// - Remark: No error is thrown when the key is not found.
    public func deleteItem(_ forKey: String) throws {
        guard !forKey.isEmpty else {
            logger.error("The forKey argument is invalid.")
            throw KeychainError.invalidKey
        }
        
        // Construct the dictionary to query the keychain.
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: serviceName,
                                    kSecAttrAccount as String: forKey]
        
        let status = SecItemDelete(query as CFDictionary)
        logger.info("Item '\(forKey, privacy: .public)' deleted from keychain: \(status == errSecSuccess, privacy: .public)")
        
        guard status == errSecSuccess || status == errSecItemNotFound else {
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "Unknown error"
            logger.error("Error occured performing the operation. \(message, privacy: .public)")
            throw KeychainError.unhandledError(message: message)
        }
    }
    
    /// Reads a value from the keychain.
    /// - Parameters:
    ///   - forKey: The key with which to associate the value.
    ///   - type: The type of the value to decode from the Keychain value.
    /// - Returns: The value of type `T`.
    ///
    /// ```swift
    /// struct Person {
    ///    var name: String
    ///    var age: Int
    /// }
    ///
    /// guard let person = try? KeychainService.default.readItem("account", type: Person.self) else {
    ///    return
    /// }
    ///
    /// print(person)
    /// ```
    public func readItem<T: Codable>(_ forKey: String, type: T.Type) throws -> T {
        let data = try readItem(forKey)
        
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
    public func readItem(_ forKey: String) throws -> Data {
        guard !forKey.isEmpty else {
            logger.error("The forKey argument is invalid.")
            throw KeychainError.invalidKey
        }
        
        // Construct the dictionary to query the Keychain.
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: forKey,
            kSecReturnData as String: true]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        // Check the status for an error.
        guard status == errSecSuccess else {
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "Unknown error"
            
            switch status {
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
        
        // Attempt to decode the value back to it's type.
        guard let result = item as? Data else {
            logger.warning("Invalid data associated with key '\(forKey, privacy: .public)'")
            throw KeychainError.unexpectedData
        }

        return result
    }
    
    /// Query the keychain for a matching key.
    /// - Parameter forKey: The key with which to query.
    /// - Returns:`true` if the key exists, otherwise `false`.
    ///
    /// If the key has been generated requiring authentication for access, the UI has been surpressed.  Therefore the function will return `true` under the following conditions:
    /// - `errSecSuccess` The item was found, no error.
    /// - `errSecInteractionNotAllowed` The item was found, the user interaction is not allowed.
    /// - `errSecAuthFailed` The item was found, but invalidated due to a change to biometry or passphrase.
    ///
    /// ```swift
    /// let result = KeychainService.default.itemExists("greeting")
    /// print(result)
    /// ```
    public func itemExists(_ forKey: String) -> Bool {
        // Construct a LAContext to surpress any biometry to access the key.
        let context = LAContext()
        context.interactionNotAllowed = true
        
        // Construct the dictionary to query the Keychain.
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: forKey,
            kSecUseAuthenticationContext as String: context]
        
        let status = SecItemCopyMatching(query as CFDictionary, nil)

        logger.info("Item '\(forKey, privacy: .public)' exists in keychain: \(status == errSecSuccess || status == errSecInteractionNotAllowed || status == errSecAuthFailed, privacy: .public)")

        return status == errSecSuccess || status == errSecInteractionNotAllowed || status == errSecAuthFailed
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
    
    /// Renames an item in the Keychain.
    /// - Parameters:
    ///   - forKey: The unique identifer of the key.
    ///   - newKey: The new unique identifier of the key.
    ///
    /// ```swift
    /// do {
    ///    try KeychainHelper.default.rename("oldKey", newKey: "newKey")
    /// }
    /// catch let error {
    ///    print(error.localizedDescription)
    /// }
    /// ```
    public func renameItem(_ forKey: String, newKey: String) throws {
        // Construct a LAContext to surpress any biometry to access the key.
        let context = LAContext()
        context.interactionNotAllowed = true
        
        // Construct the dictionary to query the Keychain.
        let findQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: forKey,
            kSecUseAuthenticationContext as String: context]

        let updateQuery: [String: Any] = [
            kSecAttrAccount as String: newKey
        ]

        let status = SecItemUpdate(findQuery as CFDictionary, updateQuery as CFDictionary)
        logger.info("Rename key from '\(forKey, privacy: .public)' to '\(newKey, privacy: .public)': \(status == errSecSuccess, privacy: .public)")
      
        
        guard status == errSecSuccess else {
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "Unknown error"
            logger.error("Error occured performing the operation. \(message, privacy: .public)")
            throw KeychainError.unhandledError(message: message)
        }
    }
}
