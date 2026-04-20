//
// Copyright contributors to the IBM Verify Core SDK for iOS project
//

import XCTest
@testable import Core
import LocalAuthentication

class KeychainServiceTests: XCTestCase {
    struct Person: Codable {
        var name: String
        var age: Int
        var acive: Bool
        var createdDate: Date
    }

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    // MARK: - Add Tests
    
    /// Adds  `Data` then removes the keychain item.
    func testAddAndDeleteItemData() throws {
        // Given
        var result = true
        
        do {
            // When
            try KeychainService.default.addItem("greeting", value: "Hello World".data(using: .utf8)!)
        
            // Then
            try KeychainService.default.deleteItem("greeting")
        }
        catch {
            result = false
        }
        
        // Then
        #if targetEnvironment(simulator)       // Expected to fail due to lack of entitlement support in SPM
        XCTAssertFalse(result)
        #else
        XCTAssertTrue(result)
        #endif
    }

    /// Adds a `String` then removes the keychain item.
    func testAddAndDeleteItemString() throws {
        // Given
        var result = true
        
        // When
        do {
            try KeychainService.default.addItem("greeting", value: "Hello World")
            try KeychainService.default.deleteItem("greeting")
        }
        catch {
            result = false
        }
        
        // Then
        #if targetEnvironment(simulator)       // Expected to fail due to lack of entitlement support in SPM
        XCTAssertFalse(result)
        #else
        XCTAssertTrue(result)
        #endif
    }
    
    /// Adds a `String` then removes the keychain item.
    func testAddUpdateAndDeleteItemString() throws {
        // Given
        var result = true
        
        // When
        do {
            try KeychainService.default.addItem("greeting", value: "Hello World")
            try KeychainService.default.addItem("greeting", value: "World Hello")
            
            let value = try KeychainService.default.readItem("greeting", type: String.self)
            
            XCTAssertEqual(value, "World Hello")
            
            // Then
            try KeychainService.default.deleteItem("greeting")
        }
        catch {
            result = false
        }
        
        // Then
        #if targetEnvironment(simulator)       // Expected to fail due to lack of entitlement support in SPM
        XCTAssertFalse(result)
        #else
        XCTAssertTrue(result)
        #endif
    }
    
    /// Adds a private key then removes the keychain item.
    func testAddAndDeletePrivateKey() throws {
        // Given
        var result = true
        
        // When
        do {
            let privateKey = RSA.Signing.PrivateKey(keySize: .bits2048)
            let derRepresentation = privateKey.derRepresentation
            
            try KeychainService.default.addItem("privateKey", value: .key(value: privateKey.derRepresentation, size: 2048, algorithm: .RSA))
            
            let value = try KeychainService.default.readItem("privateKey", type: Data.self)
            
            XCTAssertEqual(value, derRepresentation)
            
            // Then
            try KeychainService.default.deleteItem("privateKey")
        }
        catch {
            result = false
        }
        
        // Then
        #if targetEnvironment(simulator)       // Expected to fail due to lack of entitlement support in SPM
        XCTAssertFalse(result)
        #else
        XCTAssertTrue(result)
        #endif
    }
    
    /// Adds a `String` with access control of `.userPresence`.
    /// - note: Will fail tracked againt [https://feedbackassistant.apple.com/feedback/82890873](https://feedbackassistant.apple.com/feedback/82890873)
    func testAddAndDeleteItemStringWithUserPresense() throws {
        // Given
        var result = true

        // When
        do {
            try KeychainService.default.addItem("greeting", value: "Hello World", accessControl: .userPresence)
            
            // Then
            try KeychainService.default.deleteItem("greeting")
            
            // Then
            try KeychainService.default.deleteItem("privateKey")
        }
        catch {
            result = false
        }
        
        // Then
        #if targetEnvironment(simulator)       // Expected to fail due to lack of entitlement support in SPM
        XCTAssertFalse(result)
        #else
        XCTAssertTrue(result)
        #endif
    }
    
    /// Adds a `String` with access control of `.biometryCurrentSet`.
    /// - note: Will fail tracked againt [https://feedbackassistant.apple.com/feedback/82890873](https://feedbackassistant.apple.com/feedback/82890873)
    func testAddAndDeleteItemStringWithBiometryCurrentSet() throws {
        // Given
        var result = true

        // When
        do {
            try KeychainService.default.addItem("greeting", value: "Hello World", accessControl: .biometryCurrentSet)
            // Then
            try KeychainService.default.deleteItem("greeting")
        }
        catch {
            result = false
        }
        
        // Then
        #if targetEnvironment(simulator)       // Expected to fail due to lack of entitlement support in SPM
        XCTAssertFalse(result)
        #else
        XCTAssertTrue(result)
        #endif
    }
    
    /// Adds a `String` with access control of `.biometryAny`.
    /// - note: Will fail tracked againt [https://feedbackassistant.apple.com/feedback/82890873](https://feedbackassistant.apple.com/feedback/82890873)
    func testAddAndDeleteItemStringWithBiometryAny() throws {
        // Given
        var result = true

        // When
        do {
            try KeychainService.default.addItem("greeting", value: "Hello World", accessControl: .biometryAny)
            // Then
            try KeychainService.default.deleteItem("greeting")
        }
        catch {
            result = false
        }
        
        // Then
        #if targetEnvironment(simulator)       // Expected to fail due to lack of entitlement support in SPM
        XCTAssertFalse(result)
        #else
        XCTAssertTrue(result)
        #endif
    }
    
    /// Adds a `String` with access control of `.devicePasscode`.
    /// - note: Will fail tracked againt [https://feedbackassistant.apple.com/feedback/82890873](https://feedbackassistant.apple.com/feedback/82890873)
    func testAddAndDeleteItemStringWithDevicePasscode() throws {
        // Given
        var result = true

        // When
        do {
            try KeychainService.default.addItem("greeting", value: "Hello World", accessControl: .devicePasscode)
            // Then
            try KeychainService.default.deleteItem("greeting")
        }
        catch {
            result = false
        }
        
        // Then
        #if targetEnvironment(simulator)       // Expected to fail due to lack of entitlement support in SPM
        XCTAssertFalse(result)
        #else
        XCTAssertTrue(result)
        #endif
    }
    
    /// Adds a `String` with accessibility control of `.unlock`.
    func testAddAndDeleteItemStringWithUnlock() throws {
        // Given
        var result = true

        // When
        do {
            try KeychainService.default.addItem("greeting", value: "Hello World", accessibility: .whenUnlocked)
            // Then
            try KeychainService.default.deleteItem("greeting")
        }
        catch {
            result = false
        }
        
        // Then
        #if targetEnvironment(simulator)       // Expected to fail due to lack of entitlement support in SPM
        XCTAssertFalse(result)
        #else
        XCTAssertTrue(result)
        #endif
    }
    
    /// Adds a `String` with accessibility control of `.whenUnlockedThisDeviceOnly`.
    func testAddAndDeleteItemStringWithUnlockThisDeviceOnly() throws {
        // Given
        var result = true

        // When
        do {
            try KeychainService.default.addItem("greeting", value: "Hello World", accessibility: .whenUnlockedThisDeviceOnly)
            // Then
            try KeychainService.default.deleteItem("greeting")
        }
        catch {
            result = false
        }
        
        // Then
        #if targetEnvironment(simulator)       // Expected to fail due to lack of entitlement support in SPM
        XCTAssertFalse(result)
        #else
        XCTAssertTrue(result)
        #endif
    }
    
    /// Adds a `String` with accessibility control of `.afterFirstUnlock`.
    func testAddAndDeleteItemStringWithFirstUnlock() throws {
        // Given
        var result = true

        // When
        do {
            try KeychainService.default.addItem("greeting", value: "Hello World", accessibility: .afterFirstUnlock)
            // Then
            try KeychainService.default.deleteItem("greeting")
        }
        catch {
            result = false
        }
        
        // Then
        #if targetEnvironment(simulator)       // Expected to fail due to lack of entitlement support in SPM
        XCTAssertFalse(result)
        #else
        XCTAssertTrue(result)
        #endif
    }
    
    /// Adds a `String` with accessibility control of `.afterFirstUnlockThisDeviceOnly`.
    func testAddAndDeleteItemStringWithFirstUnlockThisDevice() throws {
        // Given
        var result = true

        // When
        do {
            try KeychainService.default.addItem("greeting", value: "Hello World", accessibility: .afterFirstUnlockThisDeviceOnly)
            // Then
            try KeychainService.default.deleteItem("greeting")
        }
        catch {
            result = false
        }
        
        // Then
        #if targetEnvironment(simulator)       // Expected to fail due to lack of entitlement support in SPM
        XCTAssertFalse(result)
        #else
        XCTAssertTrue(result)
        #endif
    }
    
    /// Adds, then deletes a `struct`.
    func testAddAndDeleteItemStrut() throws {
        // Given
        var result = true
        let person = Person(name: "John Doe", age: 32, acive: true, createdDate: Date())
    

        // When
        do {
            try KeychainService.default.addItem("account", value: person)
            // Then
            try KeychainService.default.deleteItem("account")
        }
        catch {
            result = false
        }
        
        // Then
        #if targetEnvironment(simulator)       // Expected to fail due to lack of entitlement support in SPM
        XCTAssertFalse(result)
        #else
        XCTAssertTrue(result)
        #endif
    }
    
    /// Adds, then deletes a `Bool`.
    func testAddAndDeleteItemBool() throws {
        // Given
        var result = true
       
        // When
        do {
            try KeychainService.default.addItem("active", value: false)
            // Then
            try KeychainService.default.deleteItem("active")
        }
        catch {
            result = false
        }
        
        // Then
        #if targetEnvironment(simulator)       // Expected to fail due to lack of entitlement support in SPM
        XCTAssertFalse(result)
        #else
        XCTAssertTrue(result)
        #endif
    }
    
    /// Adds, then deletes a `Double`.
    func testAddAndDeleteItemDouble() throws {
        // Given
        var result = true
       
        // When
        do {
            try KeychainService.default.addItem("amount", value: 123.456)
            // Then
            try KeychainService.default.deleteItem("amount")
        }
        catch {
            result = false
        }
        
        // Then
        #if targetEnvironment(simulator)       // Expected to fail due to lack of entitlement support in SPM
        XCTAssertFalse(result)
        #else
        XCTAssertTrue(result)
        #endif
    }
    
    /// Adds, then deletes a `Date`.
    func testAddAndDeleteItemDate() throws {
        // Given
        var result = true
       
        // When
        do {
            try KeychainService.default.addItem("createdDate", value: Date())
            // Then
            try KeychainService.default.deleteItem("createdDate")
        }
        catch {
            result = false
        }
        
        // Then
        #if targetEnvironment(simulator)       // Expected to fail due to lack of entitlement support in SPM
        XCTAssertFalse(result)
        #else
        XCTAssertTrue(result)
        #endif
    }
    
    /// Fails to add a keychain item, throwing an `invalidKey` error.
    func testAddItemInvalidKey() throws {
        // Given
        var thrownError: Error?

        // When
        XCTAssertThrowsError(try KeychainService.default.addItem("", value: "Hello World")) {
            thrownError = $0
        }

        // Then
        XCTAssertTrue(thrownError is KeychainError, "Unexpected error type: \(type(of: thrownError))")

        // Then
        XCTAssertEqual(thrownError as? KeychainError, .invalidKey)
    }
    
    /// Attempts to add a duplicate key throwing `duplicateKey` error.
    func testAddItemDuplicatedKey() throws {
        // Given
        var thrownError: Error?
        
        // When
        try? KeychainService.default.addItem("greeting", value: "Hello World")
        
        // When
        XCTAssertThrowsError(try KeychainService.default.addItem("greeting", value: "Hello World")) {
            thrownError = $0
        }
        
        // Then
        do {
            try KeychainService.default.deleteItem("greeting")
            
            // Then
            XCTAssertTrue(thrownError is KeychainError, "Unexpected error type: \(type(of: thrownError))")
        }
        catch {
            #if targetEnvironment(simulator)
            // Then
            XCTAssertEqual(thrownError as? KeychainError, .unhandledError(message: "A required entitlement isn't present."))
            #else
            // Then
            XCTAssertEqual(thrownError as? KeychainError, .duplicateKey)
            #endif
        }
    }
    
    
    // MARK: - Read Tests
    
    /// Adds, read then deletes a `Double`.
    func testAddReadAndDeleteItemDouble() throws {
        // Given
        var result: Double = 0
        let value = 123.456
       
        // When
        do {
            try KeychainService.default.addItem("amount", value: value)
            
            result = try KeychainService.default.readItem("amount", type: Double.self)
            
            // Then
            try KeychainService.default.deleteItem("amount")
        }
        catch let error {
            #if targetEnvironment(simulator)
            // Then
            XCTAssertEqual(error as? KeychainError, .unhandledError(message: "A required entitlement isn't present."))
            #else
            // Then
            XCTAssertEqual(value, result)
            #endif
        }
    }
    
    /// Adds, read then deletes a `String`.
    func testAddReadAndDeleteItemData() throws {
        // Given
        var result: Data = Data()
        let value = "Hello world".data(using: .utf8)!
       
        // When
        do {
            try KeychainService.default.addItem("greeting", value: value)
            result = try KeychainService.default.readItem("greeting")
            
            // Then
            try KeychainService.default.deleteItem("greeting")
        }
        catch let error {
            #if targetEnvironment(simulator)
            // Then
            XCTAssertEqual(error as? KeychainError, .unhandledError(message: "A required entitlement isn't present."))
            #else
            // Then
            XCTAssertEqual(value, result)
            #endif
        }
    }
    
    /// Adds, read then deletes a `String`.
    func testAddReadAndDeleteItemString() throws {
        // Given
        var result = ""
        let value = "Hello world"
       
        // When
        do {
            try KeychainService.default.addItem("greeting", value: value)
            result = try KeychainService.default.readItem("greeting", type: String.self)
            // Then
            try KeychainService.default.deleteItem("greeting")
        }
        catch let error {
            #if targetEnvironment(simulator)
            // Then
            XCTAssertEqual(error as? KeychainError, .unhandledError(message: "A required entitlement isn't present."))
            #else
            // Then
            XCTAssertEqual(value, result)
            #endif
        }
    }
    
    /// Adds, read then deletes a `Struct`.
    func testAddReadAndDeleteItemStruct() throws {
        // Given
        var result: Person?
        let value = Person(name: "John Doe", age: 32, acive: true, createdDate: Date())
       
        // When
        do {
            try KeychainService.default.addItem("account", value: value)
            result = try KeychainService.default.readItem("account", type: Person.self)
            // Then
            try KeychainService.default.deleteItem("account")
        }
        catch let error {
            #if targetEnvironment(simulator)
            // Then
            XCTAssertEqual(error as? KeychainError, .unhandledError(message: "A required entitlement isn't present."))
            #else
            // Then
            XCTAssertEqual(value, result)
            #endif
        }
    }
    
    /// Adds, read then deletes a `Struct`.
    func testAddReadAndDeleteItemStruct2() throws {
        // Given
        let value = Person(name: "John Doe", age: 32, acive: true, createdDate: Date())
        let result: Person
        
        // When
        do {
            try KeychainService.default.addItem("account", value: value)
            
            // Then
            result = try KeychainService.default.readItem("account", type: Person.self)
            
            // Then
            try KeychainService.default.deleteItem("account")
        }
        catch let error {
            #if targetEnvironment(simulator)
            // Then
            XCTAssertEqual(error as? KeychainError, .unhandledError(message: "A required entitlement isn't present."))
            #else
            // Then
            XCTAssertEqual(value.name, result.name)
            #endif
        }
    }
    
    /// Adds, read then deletes failig on the decoding.
    func testAddReadDeleateDecodeFail() throws {
        // Given
        var thrownError: Error?
        let value = Person(name: "John Doe", age: 32, acive: true, createdDate: Date())
       
        // When
        do {
            try KeychainService.default.addItem("account", value: value)
        
            // When
            XCTAssertThrowsError(try KeychainService.default.readItem("account", type: String.self)) {
                thrownError = $0
            }
     
            // Then
            try KeychainService.default.deleteItem("account")
        }
        catch let error {
            #if targetEnvironment(simulator)
            // Then
            XCTAssertEqual(error as? KeychainError, .unhandledError(message: "A required entitlement isn't present."))
            #else
            // Then
            XCTAssertEqual(thrownError as? KeychainError, .unexpectedData)
            #endif
        }
    }
    
    /// Attempts to read an item that doesn't exist
    func testReadNoKeyFail() throws {
        // Given
        var thrownError: Error?
        
        // When
        XCTAssertThrowsError(try KeychainService.default.readItem("nokey", type: String.self)) {
            thrownError = $0
        }
        
        // Then
        #if targetEnvironment(simulator)       // Expected to fail due to lack of entitlement support in SPM
        XCTAssertEqual(thrownError as? KeychainError, .unhandledError(message: "A required entitlement isn't present."))
        #else
        // Then
        XCTAssertEqual(thrownError as? KeychainError, .invalidKey)
        #endif
    }
    
    
    // MARK: - Delete Tests
    
    /// Fails to delete a keychain item, throwing an `invalidKey` error.
    func testDeleteItemInvalidKey() throws {
        // Given
        var thrownError: Error?

        // When
        XCTAssertThrowsError(try KeychainService.default.deleteItem("")) {
            thrownError = $0
        }
        
        // Then
        XCTAssertTrue(thrownError is KeychainError, "Unexpected error type: \(type(of: thrownError))")

        // Then
        XCTAssertEqual(thrownError as? KeychainError, .invalidKey)
    }
    
    /// Delete a keychain item and only throws an error on an unhandled exception occuring in the SecKey methods.
    func testDeleteItem() throws {
        // Given
        var result = true
        
        // When
        do {
            try KeychainService.default.deleteItem("greeting")
        }
        catch {
            result = false
        }
        
        // Then
        #if targetEnvironment(simulator)       // Expected to fail due to lack of entitlement support in SPM
        XCTAssertFalse(result)
        #else
        XCTAssertTrue(result)
        #endif
    }
    
    // MARK: - Exists Test
    /// Adds a `String`, queries for the key, then delete.
    func testAddExistsThenDelete() throws {
        // Given
        var result = true

        // When
        do {
            try KeychainService.default.addItem("greeting", value: "Hello World")
            result = KeychainService.default.itemExists("greeting")
            // Then
            try KeychainService.default.deleteItem("greeting")
        }
        catch {
            result = false
        }
        
        // Then
        #if targetEnvironment(simulator)       // Expected to fail due to lack of entitlement support in SPM
        XCTAssertFalse(result)
        #else
        XCTAssertTrue(result)
        #endif
    }
    
    /// Queries for the key which doesn't exist.
    func testNoKeyExists() throws {
        // Given, When
        let result = KeychainService.default.itemExists("nokey")
        
        // Then
        XCTAssertFalse(result)
    }
    
    // MARK: - Rename Test
    /// Creates a new item, then rename, then delete.
    func testAddKeyRenameDelete() throws {
        // Given
        var result = true

        // When
        do {
            try KeychainService.default.addItem("greeting", value: "Hello World")
        
            try KeychainService.default.renameItem("greeting", newKey: "welcome")
            // Then
            try KeychainService.default.deleteItem("welcome")
        }
        catch {
            result = false
        }
        
        // Then
        #if targetEnvironment(simulator)       // Expected to fail due to lack of entitlement support in SPM
        XCTAssertFalse(result)
        #else
        XCTAssertTrue(result)
        #endif
    }
    
    /// Creates a new item, then rename.
    func testAddKeyRenameFail() throws {
        // Given
        var result = true

        // When
        do {
            try KeychainService.default.addItem("greeting", value: "Hello World")
        
            try KeychainService.default.renameItem("greeting", newKey: "welcome")
            // Then
            try KeychainService.default.deleteItem("welcome")
        }
        catch {
            result = false
        }
        
        // Then
        #if targetEnvironment(simulator)       // Expected to fail due to lack of entitlement support in SPM
        XCTAssertFalse(result)
        #else
        XCTAssertTrue(result)
        #endif
    }
    
    // MARK: - Accessibility Tests
    
    /// Initializes a new SecAccessible.whenUnlockedThisDeviceOnly
    func testInitAccessibilityUnlock() throws {
        // Given, When
        guard let result = SecAccessible(rawValue: kSecAttrAccessibleWhenUnlockedThisDeviceOnly) else {
            XCTFail("Invalid kSecAttrAccessible type.")
            return
        }
        
        // Then
        XCTAssertEqual(result, .whenUnlockedThisDeviceOnly)
    }
    
    /// Initializes a new SecAccessible.afterFirstUnlockThisDeviceOnly
    func testInitAccessibilityFirstUnlockDevice() throws {
        // Given, When
        guard let result = SecAccessible(rawValue: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly) else {
            XCTFail("Invalid kSecAttrAccessible type.")
            return
        }
        
        // Then
        XCTAssertEqual(result, .afterFirstUnlockThisDeviceOnly)
    }
    
    /// Initializes a new SecAccessible.afterFirstUnlock
    func testInitAccessibilityAfterFirstUnlockDevice() throws {
        // Given, When
        guard let result = SecAccessible(rawValue: kSecAttrAccessibleAfterFirstUnlock) else {
            XCTFail("Invalid kSecAttrAccessible type.")
            return
        }
        
        // Then
        XCTAssertEqual(result, .afterFirstUnlock)
    }
    
    /// Initializes a new SecAccessible.whenUnlocked
    func testInitAccessibilityUnlockDevice() throws {
        // Given, When
        guard let result = SecAccessible(rawValue: kSecAttrAccessibleWhenUnlocked) else {
            XCTFail("Invalid kSecAttrAccessible type.")
            return
        }
        
        // Then
        XCTAssertEqual(result, .whenUnlocked)
    }
    
    /// Initializes a new SecAccessible but invalid
    func testInitAccessibilityInvalid() throws {
        // Given, When
        let result = SecAccessible(rawValue: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly)
        
        // Then
        XCTAssertNil(result)
    }
    
    /// Confirms the kSecAttrAccessible against the enum values.
    func testAccessibilityRawValues() throws {
        // Given, When, Then
        XCTAssertEqual(SecAccessible.whenUnlockedThisDeviceOnly.rawValue, kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
        
        XCTAssertEqual(SecAccessible.whenUnlocked.rawValue, kSecAttrAccessibleWhenUnlocked)
        
        XCTAssertEqual(SecAccessible.afterFirstUnlockThisDeviceOnly.rawValue, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
        
        XCTAssertEqual(SecAccessible.afterFirstUnlock.rawValue, kSecAttrAccessibleAfterFirstUnlock)
    }
    
    // MARK: - Access Control Tests
    
    /// Initializes a new SecAccessControl.devicePasscode
    func testInitAccessControlDevicePasscode() throws {
        // Given, When
        guard let result = SecAccessControl(rawValue: SecAccessControlCreateFlags.devicePasscode) else {
            XCTFail("Invalid SecAccessControlCreateFlags.")
            return
        }
        
        // Then
        XCTAssertEqual(result, .devicePasscode)
    }
    
    /// Initializes a new SecAccessControl.biometryAny
    func testInitAccessControlAnyBiometry() throws {
        // Given, When
        guard let result = SecAccessControl(rawValue: SecAccessControlCreateFlags.biometryAny) else {
            XCTFail("Invalid SecAccessControlCreateFlags.")
            return
        }
        
        // Then
        XCTAssertEqual(result, .biometryAny)
    }
    
    /// Initializes a new SecAccessControl.biometryCurrentSet
    func testInitAccessControlBiometryCurrentSet() throws {
        // Given, When
        guard let result = SecAccessControl(rawValue: SecAccessControlCreateFlags.biometryCurrentSet) else {
            XCTFail("Invalid SecAccessControlCreateFlags.")
            return
        }
        
        // Then
        XCTAssertEqual(result, .biometryCurrentSet)
    }
    
    /// Initializes a new SecAccessControl.userPresence
    func testInitAccessControlUserPresence() throws {
        // Given, When
        guard let result = SecAccessControl(rawValue: SecAccessControlCreateFlags.userPresence) else {
            XCTFail("Invalid SecAccessControlCreateFlags.")
            return
        }
        
        // Then
        XCTAssertEqual(result, .userPresence)
    }
    
    /// Initializes a new SecAccessControl but invalid
    func testInitAccessControlInvalid() throws {
        // Given, When
        let result = SecAccessControl(rawValue: SecAccessControlCreateFlags.applicationPassword)
        
        // Then
        XCTAssertNil(result)
    }
    
    /// Confirms the SecAccessControlCreateFlags against the enum values.
    func testAccessControlRawValues() throws {
        // Given, When, Then
        XCTAssertEqual(SecAccessible.whenUnlockedThisDeviceOnly.rawValue, kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
        
        XCTAssertEqual(SecAccessible.whenUnlocked.rawValue, kSecAttrAccessibleWhenUnlocked)
        
        XCTAssertEqual(SecAccessible.afterFirstUnlockThisDeviceOnly.rawValue, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
        
        XCTAssertEqual(SecAccessible.afterFirstUnlock.rawValue, kSecAttrAccessibleAfterFirstUnlock)
    }
    
    // MARK: - PolicyDomainStateChanged Tests
    
    /// No biometry domain state has changed.
    /// - note: Will fail tracked againt [https://feedbackassistant.apple.com/feedback/82890873](https://feedbackassistant.apple.com/feedback/82890873)
    func testHasPolicyDomainStateChangedValid() throws {
        // Given
        let context = LAContext()
        let initialState = context.evaluatedPolicyDomainState
           
        // When
        let result = KeychainService.default.hasPolicyDomainStateChanged(initialState)
        
        // Then
        #if targetEnvironment(simulator)       // Expected to fail due to lack of entitlement support in SPM
        XCTAssertTrue(result)
        #else
        XCTAssertFalse(result)
        #endif
    }
    
    /// Biometry domain state has changed.
    func testHasPolicyDomainStateChangedInvalid() throws {
        // Given, When
        let result = KeychainService.default.hasPolicyDomainStateChanged(nil)
        
        // Then
        XCTAssertTrue(result)
    }
}
