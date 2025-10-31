//
// Copyright contributors to the IBM Verify Core SDK for iOS project
//

import XCTest
import CryptoKit
@testable import Core

class CryptoKitExtensionTests: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    // MARK: - Private key operations
    
    /// Test the creation of a new RSA private key.
    func testCreatePrivateKey() throws {
        // Given, Where
        let key = RSA.Signing.PrivateKey()
        
        // Then
        XCTAssertNotNil(key)
        
        // Then
        XCTAssertEqual(key.sizeInBits, 2048)
    }
    
    /// Test recreating the private key from invalid DER representation.
    func testCreatePrivateKeyInvalidDER() throws {
        // Given, Where
        let data = "hello world".data(using: .utf8)!
        var thrownError: Error!
        
        // When
        XCTAssertThrowsError(try RSA.Signing.PrivateKey(derRepresentation: data)) {
            thrownError = $0
        }
     
        // Then
        XCTAssertNotNil(thrownError)
    }
    
    /// Test the creation of a new RSA private key of 2048 bits.
    func testCreatePrivateKey2048Bits() throws {
        // Given, Where
        let key = RSA.Signing.PrivateKey(keySize: .bits2048)
        
        // Then
        XCTAssertNotNil(key)
        
        // Then
        XCTAssertEqual(key.sizeInBits, 2048)
    }
    
    /// Test the creation of a new RSA private key of 3072 bits.
    func testCreatePrivateKey3072Bits() throws {
        // Given, Where
        let key = RSA.Signing.PrivateKey(keySize: .bits3072)
        
        // Then
        XCTAssertNotNil(key)
        
        // Then
        XCTAssertEqual(key.sizeInBits, 3072)
    }
    
    /// Test the creation of a new RSA private key of 4096 bits.
    func testCreatePrivateKey4096Bits() throws {
        // Given, Where
        let key = RSA.Signing.PrivateKey(keySize: .bits4096)
        
        // Then
        XCTAssertNotNil(key)
        
        // Then
        XCTAssertEqual(key.sizeInBits, 4096)
    }
    
    /// Test the creation of a RSA private key from a DER representable.
    func testCreatePrivateKeyFromDER() throws {
        // Given
        let key = RSA.Signing.PrivateKey()
        
        // Where
        let data = key.derRepresentation
        
        // Then
        let newKey = try RSA.Signing.PrivateKey(derRepresentation: data)
        XCTAssertNotNil(newKey)
            
        // Then
        XCTAssertEqual(key.derRepresentation, newKey.derRepresentation)
    }
    
    /// Test to return the underlying keyt from the private key.
    func testGetPrivateKeySecKey() throws {
        // Given
        let key = RSA.Signing.PrivateKey()
        
        let secKey = key.keyRepresentation
        
        // Then
        XCTAssertNotNil(secKey)
    }
    
    /// Test data signing with the rpivate key.
    func testCreateSignatureDefaultSHA512() throws {
        // Given
        let key = RSA.Signing.PrivateKey()
        
        // Where
        let value = "hello world".data(using: .utf8)!
        
        // Then
        let signature = try key.signature(for: value)
        
        // Then
        XCTAssertNotNil(signature)
    }
    
    // MARK: - Public key operations
    
    /// Test creating a public key from the private key.
    func testCreatePublicKey() throws {
        // Given
        let key = RSA.Signing.PrivateKey()
        
        // When
        let publicKey = key.publicKey
        
        // Then
        XCTAssertNotNil(publicKey)
        
        // Then
        XCTAssertEqual(publicKey.sizeInBits, 2048)
    }

    /// Test recreating the public key from the DER representation.
    func testCreatePublicKeyDER() throws {
        // Given
        let key = RSA.Signing.PrivateKey().publicKey
        
        // When
        let data = key.derRepresentation
        
        // Then
        let newKey = try RSA.Signing.PublicKey(derRepresentation: data)
        XCTAssertNotNil(newKey)
        
        // Then
        XCTAssertEqual(key.derRepresentation, newKey.derRepresentation)
    }
    
    /// Test recreating the public key from invalid DER representation.
    func testCreatePublicKeyInvalidDER() throws {
        // Given, Where
        let data = "hello world".data(using: .utf8)!
        var thrownError: Error!
        
        // When
        XCTAssertThrowsError(try RSA.Signing.PublicKey(derRepresentation: data)) {
            thrownError = $0
        }
     
        // Then
        XCTAssertNotNil(thrownError)
    }
    
    /// Test to generate the PEM format from the public key.
    func testGetPublicKeyPEM() throws {
        // Given
        let key = RSA.Signing.PrivateKey().publicKey
        
        let data = key.pemRepresentation
        
        // Then
        XCTAssertNotNil(data)
    }
    
    /// Test to generate the JWK format from the public key.
    func testGetPublicKeyJWK() throws {
        // Given
        let key = RSA.Signing.PrivateKey().publicKey
        
        let data = key.jwkRepresentation
        
        // Then
        XCTAssertNotNil(data)
    }
    
    /// Test to return the underlying keyt from the public key.
    func testGetPublicKeySecKey() throws {
        // Given
        let key = RSA.Signing.PrivateKey().publicKey
        
        let secKey = key.keyRepresentation
        
        // Then
        XCTAssertNotNil(secKey)
    }
    
    func testGetPublicKeyX509() throws {
        // Given
        let key = RSA.Signing.PrivateKey().publicKey
        
        // When/
        let data = key.x509Representation
        
        // Then
        XCTAssertNotNil(data)
    }
    
    /// Test generating a signature with default SHA512 algorithm.
    func testVerifySignature() throws {
        // Given
        let key = RSA.Signing.PrivateKey()
        let publicKey = key.publicKey
        
        // Where
        let value = "hello world".data(using: .utf8)!
        
        // Then
        let signature = try key.signature(for: value)
        XCTAssertNotNil(signature)
            
        // Then
        let result = publicKey.isValidSignature(signature, for: value)
        XCTAssertTrue(result)
    }
    
    /// Test generating a signature with SHA1 algorithm.
    func testVerifySignatureSHA1Digest() throws {
        // Given
        let key = RSA.Signing.PrivateKey()
        let publicKey = key.publicKey
        
        // Where
        let value = Insecure.SHA1.hash(data: "hello world".data(using: .utf8)!)
        
        // Then
        let signature = try key.signature(for: value)
        XCTAssertNotNil(signature)
        
        // Then
        let result = publicKey.isValidSignature(signature, for: value)
        XCTAssertTrue(result)
    }
    
    /// Test generating a signature with SHA256 algorithm.
    func testVerifySignature256Digest() throws {
        // Given
        let key = RSA.Signing.PrivateKey()
        let publicKey = key.publicKey
        
        // Where
        let value = SHA256.hash(data: "hello world".data(using: .utf8)!)
        
        // Then
        let signature = try key.signature(for: value)
        XCTAssertNotNil(signature)
        
        // Then
        let result = publicKey.isValidSignature(signature, for: value)
        XCTAssertTrue(result)
    }
    
    /// Test generating a signature with SHA384 algorithm.
    func testVerifySignatureSHA384Digest() throws {
        // Given
        let key = RSA.Signing.PrivateKey()
        let publicKey = key.publicKey
        
        // Where
        let value = SHA384.hash(data: "hello world".data(using: .utf8)!)
        
        // Then
        let signature = try key.signature(for: value)
        XCTAssertNotNil(signature)
        
        // Then
        let result = publicKey.isValidSignature(signature, for: value)
        XCTAssertTrue(result)
    }
    
    /// Test generating a signature with SHA512 algorithm.
    func testVerifySignatureSHA512() throws {
        // Given
        let key = RSA.Signing.PrivateKey()
        let publicKey = key.publicKey
        
        // Where
        let value = SHA512.hash(data: "hello world".data(using: .utf8)!)
        
        // Then
        let signature = try key.signature(for: value)
        XCTAssertNotNil(signature)
        
        // Then
        let result = publicKey.isValidSignature(signature, for: value)
        XCTAssertTrue(result)
    }
    
    /// Test attempting to create a signature with an invalid algorithm.
    func testVerifySignatureFailedInvalidDigest() throws {
        // Given
        let key = RSA.Signing.PrivateKey()
        let publicKey = key.publicKey
        
        // Where
        let value = "hello world".data(using: .utf8)!
        let invalidValue = SHA256.hash(data: "hello world1".data(using: .utf8)!)
        
        // Then
        let signature = try key.signature(for: value)
        XCTAssertNotNil(signature)
        
        // Then
        let result = publicKey.isValidSignature(signature, for: invalidValue)
        XCTAssertFalse(result)
    }
    
    /// Test generating a signature with SHA512 algorithm.
    func testVerifySecKeyAlgorithmFails() throws {
        // Given
        let key = RSA.Signing.PrivateKey()
        var thrownError: Error!
        
        // Where
        let value = Insecure.MD5.hash(data: "hello world".data(using: .utf8)!)
        
        // When
        XCTAssertThrowsError(try key.signature(for: value)) {
            thrownError = $0
        }
     
        // Then
        XCTAssertNotNil(thrownError)
    }
    
    /// Test to verify the signature with invalid data used to generate the signature.
    func testVerifySignatureInvalidData() throws {
        // Given
        let key = RSA.Signing.PrivateKey()
        let publicKey = key.publicKey
        
        // Where
        let value = "hello world".data(using: .utf8)!
        let invalidValue = "hello world1".data(using: .utf8)!
        
        // Then
        let signature = try key.signature(for: value)
        XCTAssertNotNil(signature)
        
        // Then
        let result = publicKey.isValidSignature(signature, for: invalidValue)
        XCTAssertFalse(result)
    }
    
    /// Test to verify the signature with invalid digest used to generate the signature.
    func testVerifySignatureInvalidDigest() throws {
        // Given
        let key = RSA.Signing.PrivateKey()
        let publicKey = key.publicKey
        
        // Where
        let value = "hello world".data(using: .utf8)!
        let invalidValue = Insecure.MD5.hash(data: "hello world1".data(using: .utf8)!)
        
        // Then
        let signature = try key.signature(for: value)
        XCTAssertNotNil(signature)
        
        // Then
        let result = publicKey.isValidSignature(signature, for: invalidValue)
        XCTAssertFalse(result)
    }

    
    // MARK: - Signature operations
    
    /// Test create signature then recreate from raw representation.
    func testCreateSignatureFromRaw() {
        // Given
        let key = RSA.Signing.PrivateKey()
        
        // Where
        let value = "hello world".data(using: .utf8)!
        
        // Then
        let signature = try? key.signature(for: value)
        XCTAssertNotNil(signature)
        
        // Then
        let raw = signature!.rawRepresentation
        let newSignature = try? RSA.Signing.RSASignature(rawRepresentation: raw)
        XCTAssertNotNil(newSignature)
    }
    
    /// Test create signature then recreate from raw representation and verify.
    func testCreateAndVerifySignatureFromRaw() {
        // Given
        let key = RSA.Signing.PrivateKey()
        let publicKey = key.publicKey
        
        // Where
        let value = "hello world".data(using: .utf8)!
        
        // Then
        let signature = try? key.signature(for: value)
        XCTAssertNotNil(signature)
        
        // Then
        let raw = signature!.rawRepresentation
        let newSignature = try? RSA.Signing.RSASignature(rawRepresentation: raw)
        
        // Then
        let result = publicKey.isValidSignature(newSignature!, for: value)
        
        XCTAssertTrue(result)
    }
    
    /// Test create signature then write to byte[].
    func testCreateSignatureUnsafeBytes() {
        // Given
        let key = RSA.Signing.PrivateKey()
        
        // Where
        let value = "hello world".data(using: .utf8)!
        
        // Then
        let signature = try? key.signature(for: value)
        XCTAssertNotNil(signature)
        
        // Then
        let result = signature!.withUnsafeBytes { $0.load(as: UInt32.self) }
        XCTAssertNotNil(result)
    }
    
    /// Test create signature then recreate from raw representation.
    func testCreateSignatureEmptyString() {
        // Given
        let key = RSA.Signing.PrivateKey()
        
        // Where
        let value = "".data(using: .utf8)!
        
        // Then
        let signature = try? key.signature(for: value)
        XCTAssertNotNil(signature)
        
        // Then
        let raw = signature!.rawRepresentation
        let newSignature = try? RSA.Signing.RSASignature(rawRepresentation: raw)
        XCTAssertNotNil(newSignature)
    }
}
