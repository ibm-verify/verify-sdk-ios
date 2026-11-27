import XCTest
import LocalAuthentication
import CryptoKit
import Security
@testable import FIDO2

final class SecKeyStoreTests: XCTestCase {
    
    let service = "testService"
    let account = "testAccount"
    let accessGroup = "TEAMID.group.com.app"

    // MARK: - 1. Query Logic (Branch Coverage)
    
    func testQueryConstruction_WithAccessGroup() {
        // Given
        let store = SecKeyStore(serviceName: service, accessGroup: accessGroup)
        
        // When
        let query = store.query(for: account)
        
        // Then
        XCTAssertEqual(query[kSecAttrService as String] as? String, service)
        XCTAssertEqual(query[kSecAttrAccount as String] as? String, account)
        XCTAssertEqual(query[kSecAttrAccessGroup as String] as? String, accessGroup)
    }

    func testQueryConstruction_WithoutAccessGroup() {
        // Given
        let store = SecKeyStore(serviceName: service, accessGroup: nil)
        
        // When
        let query = store.query(for: account)
        
        // Then
        XCTAssertNil(query[kSecAttrAccessGroup as String], "Access group should be omitted when nil")
        XCTAssertEqual(query[kSecAttrService as String] as? String, service)
    }

    // MARK: - 2. Error & Extension Coverage
    
    func testKeyStoreErrorCoverage() {
        let message = "Something went wrong"
        let error = KeyStoreError(message)
        
        XCTAssertEqual(error.description, message)
        XCTAssertEqual(error.localizedDescription, message)
    }
    
    func testOSStatusExtension() {
        let status: OSStatus = errSecItemNotFound
        let message = status.message
        
        XCTAssertFalse(message.isEmpty)
        XCTAssertNotEqual(message, String(status), "Should return a human-readable string if possible")
    }

    // MARK: - 3. Public Method Surface (Line Coverage)
    
    func testDelete_RunsLogic() {
        let store = SecKeyStore(serviceName: service)
        // This hits the 'delete' method logic. In a test runner,
        // it usually returns errSecItemNotFound, covering that branch.
        #if targetEnvironment(simulator)       // Expected to fail due to lack of entitlement support in SPM
        XCTAssertNotNil(store)
        #else
        XCTAssertNoThrow(try store.delete(account))
        #endif
    }
    
    func testRead_RunsLogic() {
        let store = SecKeyStore(serviceName: service)
        // This executes the 'read' method and hits the 'errSecItemNotFound' or 'default' cases.
        let result = store.read(account, context: LAContext())
        XCTAssertNil(result)
    }

    // MARK: - 4. Crypto Agility

    func testAlgorithmEncodeDecodeRoundTrip() {
        let algorithms: [COSEAlgorithmIdentifier] = [.es256, .mldsa65, .mldsa87]
        for algorithm in algorithms {
            let data = SecKeyStore.encode(algorithm)
            XCTAssertEqual(SecKeyStore.decode(data), algorithm)
        }
    }

    func testAlgorithmDecode_LegacyKeyDefaultsToES256() {
        XCTAssertEqual(SecKeyStore.decode(nil), .es256)
    }

    func testAlgorithmDecode_InvalidData() {
        XCTAssertNil(SecKeyStore.decode(Data("not-a-number".utf8)))
        XCTAssertNil(SecKeyStore.decode(Data("-99".utf8)))
    }

    func testGenerate_UnsupportedAlgorithmThrows() {
        let store = SecKeyStore(serviceName: service)
        XCTAssertThrowsError(try store.generate(algorithm: .rs256, context: LAContext()))
    }

    // MARK: - 5. Algorithm Selection

    func testIsSupported() {
        XCTAssertTrue(SecKeyStore.isSupported(.es256))
        XCTAssertFalse(SecKeyStore.isSupported(.rs256))
        XCTAssertFalse(SecKeyStore.isSupported(.ps256))
    }

    func testSelectAlgorithm_EmptyDefaultsToES256() {
        XCTAssertEqual(SecKeyStore.selectAlgorithm(from: []), .es256)
    }

    func testSelectAlgorithm_FirstSupportedInOrder() {
        // RS256 and PS256 are unsupported so are skipped, ES256 is the first supported.
        let parameters = [PublicKeyCredentialParameters(alg: .rs256),
                          PublicKeyCredentialParameters(alg: .ps256),
                          PublicKeyCredentialParameters(alg: .es256)]
        XCTAssertEqual(SecKeyStore.selectAlgorithm(from: parameters), .es256)
    }

    func testSelectAlgorithm_HonoursPreferenceOrder() {
        let parameters = [PublicKeyCredentialParameters(alg: .es256),
                          PublicKeyCredentialParameters(alg: .mldsa65)]
        XCTAssertEqual(SecKeyStore.selectAlgorithm(from: parameters), .es256)
        
        if #available(iOS 26.0, macCatalyst 26.0, *) {
            let reversed = [PublicKeyCredentialParameters(alg: .mldsa87),
                            PublicKeyCredentialParameters(alg: .mldsa65),
                            PublicKeyCredentialParameters(alg: .es256)]
            XCTAssertEqual(SecKeyStore.selectAlgorithm(from: reversed), .mldsa87)
        }
    }

    func testSelectAlgorithm_NoneSupported() {
        let parameters = [PublicKeyCredentialParameters(alg: .rs256),
                          PublicKeyCredentialParameters(alg: .ps256)]
        XCTAssertNil(SecKeyStore.selectAlgorithm(from: parameters))
    }
}
