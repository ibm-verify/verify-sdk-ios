//
// Copyright contributors to the IBM Verify Core SDK for iOS project
//

import Foundation
import CryptoKit
import CommonCrypto

///RSA (Rivest–Shamir–Adleman) is a public-key cryptosystem that is widely used for secure data transmission and to share keys for symmetric-key cryptography.
public enum RSA {
}

extension RSA {
    /// A mechanism used to create keys and sign or verify a cryptographic signatures using RSA.
    public enum Signing {
        /// An RSA public key used to verify cryptographic signatures.
        public struct PublicKey {
            private var key: SecKey
            
            /// Creates a RSA pubic key from a DER representation.
            /// - Parameters:
            ///   - data: A DER-encoded representation of the key.
            public init<D>(derRepresentation data: D) throws where D : DataProtocol {
                /// Construct the SecKey.
                let attributes: [String: Any] = [
                    kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                    kSecAttrKeyClass as String: kSecAttrKeyClassPublic
                ]
                
                let data = Data(data)
                var error: Unmanaged<CFError>?
                
                guard let key = SecKeyCreateWithData(data as CFData, attributes as CFDictionary, &error) else {
                    throw error!.takeRetainedValue() as Error
                }
                
                self.key = key
            }
            
            /// Initializes the public key with `SecKey`.
            /// - Parameters:
            ///   - key: The public key generated from the private key.
            fileprivate init(_ key: SecKey) {
                self.key = key
            }
            
            /// The total number of bits in this cryptographic key.
            public var sizeInBits: Int {
                let attributes = SecKeyCopyAttributes(self.key)! as NSDictionary
                return (attributes[kSecAttrKeySizeInBits]! as! NSNumber).intValue
            }
            
            /// A Distinguished Encoding Rules (DER) encoded representation of the private key.
            ///
            /// The key is encoded as PKCS #1 format.
            public var derRepresentation: Data {
                get {
                    var error: Unmanaged<CFError>? = nil
                    let representation = SecKeyCopyExternalRepresentation(self.key, &error)
                    return representation! as Data
                }
            }
            
            /// A Privacy-Enhanced Mail (PEM) representation of the PKCS#1 public key.
            public var pemRepresentation: String {
                get {
                    var encoded = self.derRepresentation.base64EncodedString()[...]
                    let lineLength = 64
                    let lineCount = (encoded.utf8.count + lineLength) / lineLength
                    
                    var lines = [Substring]()
                    lines.reserveCapacity(lineCount + 2)
                    
                    lines.append("-----BEGIN PUBLIC KEY-----")
                    
                    while encoded.count > 0 {
                        let prefixIndex = encoded.index(encoded.startIndex, offsetBy: lineLength, limitedBy: encoded.endIndex) ?? encoded.endIndex
                        lines.append(encoded[..<prefixIndex])
                        encoded = encoded[prefixIndex...]
                    }
                    
                    lines.append("-----END PUBLIC KEY-----")
                    
                    return lines.joined(separator: "\n")
                }
            }
            
            /// A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that represents a cryptographic key.
            public var jwkRepresentation: String {
                get {
                    // Get the public key attributes.
                    let attributes = SecKeyCopyAttributes(self.key)! as NSDictionary
                    
                    // Get the v-data information.
                    let data = attributes[kSecValueData]! as! Data
                                
                    // Create the modulus and exponent from the public key attribute data.
                    var modulus  = data.subdata(in: 8..<(data.count - 5))
                    let exponent = data.subdata(in: (data.count - 3)..<data.count)

                    if modulus.count > self.sizeInBits / 8 { // --> 257 bytes
                        modulus.removeFirst(1)
                    }

                    return """
                    { \
                    "kty": "RSA", \
                    "use": "sig", \
                    "kid": "\(UUID().uuidString)", \
                    "n": "\(modulus.base64UrlEncodedString(options: [.noPaddingCharacters, .safeUrlCharacters]))", \
                    "e": "\(exponent.base64UrlEncodedString(options: [.noPaddingCharacters, .safeUrlCharacters]))" \
                    }
                    """
                }
            }
            
            /// The representation of the key as  `SecKey`.
            public var keyRepresentation: SecKey {
                return self.key
            }
            
            /// An X.509 certificate representation of the public key.
            ///
            /// - Remark: The encoding of the public key includes the ASN.1 SubjectPublicKeyInfo type.  This representation is typically compatible with external security frameworks such as Java, openSSL, PHP, Perl etc.
            public var x509Representation: String {
                get {
                    // ASN.1 identifiers
                    let ASNBitStringIdentifer: UInt8 = 0x03
                    let ASNSequenceIdentifier: UInt8 = 0x30
                    
                    // http://www.opensource.apple.com/source/security_certtool/security_certtool-55103/src/dumpasn1.cfg
                    let ASNAlgorithmIdentifer: [UInt8] = [
                        0x30, 0x0D, 0x06,   // Version, INTEGER 0
                        0x09, 0x2A,         // SEQUENCE, length 13
                        0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, // rsaEncryption OID
                        0x05, 0x00          // NULL
                    ]
                    
                    /// Returns the number of bytes required to store the receiver in a given encoding.
                    func lengthOfBytes(using value: [UInt8]) -> [UInt8] {
                        var length = value.count
                                
                        if length < 128 {
                            return [UInt8(length)]
                        }
                                
                        // Number of bytes needed to encode the length.
                        let lengthOfBytes = Int((log2(Double(length)) / 8) + 1)
                                
                        // Length of the first byte plus the remaining bytes.
                        let lengthOfFirstByte = UInt8(128 + lengthOfBytes)
                        
                        var result: [UInt8] = []
                        for _ in 0..<lengthOfBytes {
                            // Take the last 8 bits of the length.
                            let lengthOfByte = UInt8(length & 0xff)
                            
                            // Insert the lengthOfByte at the beginning of the array.
                            result.insert(lengthOfByte, at: 0)
                            
                            // Delete the last 8 bits of length.
                            length = length >> 8
                        }
                        
                        // Insert lengthOfFirstByte at the beginning of the array.
                        result.insert(lengthOfFirstByte, at: 0)
                        
                        return result
                    }
                    
                    // Construct the X.509 encoding of the DER with the SubjectPublicKeyInfo identifier.
                    var encoded: [UInt8] = [UInt8](self.derRepresentation)
                            
                    // Insert ASN.1 BIT STRING bytes at the beginning of the array
                    encoded.insert(0x00, at: 0)
                    encoded.insert(contentsOf: lengthOfBytes(using: encoded), at: 0)
                    encoded.insert(ASNBitStringIdentifer, at: 0)
                            
                    // Insert ASN.1 AlgorithmIdentifier (RSA) bytes at the beginning of the array
                    encoded.insert(contentsOf: ASNAlgorithmIdentifer, at: 0)
                            
                    // Insert ASN.1 SEQUENCE bytes at the beginning of the array
                    encoded.insert(contentsOf: lengthOfBytes(using: encoded), at: 0)
                    encoded.insert(ASNSequenceIdentifier, at: 0)
                            
                    return Data(encoded).base64EncodedString()
                }
            }
        }

        /// An RSA private key used to create cryptographic signatures.
        public struct PrivateKey {
            private var key: SecKey!
            
            /// Creates a random RSA private key for signing.
            ///
            /// - Parameters:
            ///   - keySize: The available key RSA sizes.  Default is 2048 bits.
            ///
            /// Example to create a new private key.
            /// ```
            /// // Create a new private key.
            /// let key = RSA.Signing.PrivateKey()
            /// ```
            public init(keySize: RSA.Signing.KeySize = .bits2048) {
                // Private key attributes
                let attributes: [String: Any] = [
                    kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                    kSecAttrKeySizeInBits as String: keySize.bitLength,
                    kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                    kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: false]
                ]
                
                var error: Unmanaged<CFError>?

                // Create the private key.
                let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error)
                
                guard let unwrappedKey = key else {
                    let message = error!.takeRetainedValue().localizedDescription
                    print("\tError generating private key from SecKeyCreateRandomKey. %@", message)
                    return
                }
                
                self.key = unwrappedKey
            }
            
            /// Creates a random RSA private key for signing from a data representation of the key.
            /// - Parameters:
            ///   - data: A DER-encoded representation of the key.
            public init<D>(derRepresentation data: D) throws where D : DataProtocol {
                // Private key attributes
                let attributes: [String: Any] = [
                    kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                    kSecAttrKeyClass as String: kSecAttrKeyClassPrivate
                ]
                
                let data = Data(data)
                var error: Unmanaged<CFError>?
                
                // Restore the private key.
                let key = SecKeyCreateWithData(data as CFData, attributes as CFDictionary, &error)
                
                guard let unwrappedKey = key else {
                    throw error!.takeRetainedValue() as Error
                }
                
                self.key = unwrappedKey
            }
            
            /// The total number of bits in this cryptographic key.
            public var sizeInBits: Int {
                let attributes = SecKeyCopyAttributes(self.key)! as NSDictionary
                return (attributes[kSecAttrKeySizeInBits]! as! NSNumber).intValue
            }

            /// The corresponding public key.
            ///
            /// Example to get the public key from the private key in PEM format.
            /// ```swift
            /// // Get the public key from the private key.
            /// let key = RSA.Signing.PrivateKey().publicKey
            /// let value = key.pemRepresentation
            ///
            /// // prints -----BEGIN PUBLIC KEY-----\r\n\n MIIBGfMA0GCSq...
            /// print(value)
            /// ```
            public var publicKey: RSA.Signing.PublicKey {
                get {
                    // Generate a external representation of private key.
                    return PublicKey(SecKeyCopyPublicKey(self.key)!)
                }
            }

            /// A Distinguished Encoding Rules (DER) encoded representation of the private key.
            ///
            /// The key is encoded as PKCS #1 format.
            public var derRepresentation: Data {
                get {
                    var error: Unmanaged<CFError>? = nil
                    let representation = SecKeyCopyExternalRepresentation(self.key, &error)
                    return representation! as Data
                }
            }
            
            /// The representation of the key as  `SecKey`.
            public var keyRepresentation: SecKey {
                return self.key
            }
        }
    }
}

extension RSA.Signing.PrivateKey {
    /// Creates the cryptographic signature for a block of data. SHA512 is used as the hash function.
    ///
    /// - Parameters:
    ///   - data: The data to sign.
    ///
    /// Example to generate a signature with the private key:
    /// ```swift
    /// let key = RSA.Signing.PrivateKey()
    /// let data = "hello world".data(using: .utf8)!
    ///
    /// if let signature = try? key.signature(for: data) {
    ///    let result = signature.rawRepresentation.base64UrlEncodedString()
    ///    print(result)
    /// }
    /// ```
    /// - Returns: The digital signature.
    /// - Throws: If there is a failure producing the signature.
    public func signature<D>(for data: D) throws -> RSA.Signing.RSASignature where D : DataProtocol {
        return try self.signature(for: SHA512.hash(data: data))
    }
    
    /// Creates the cryptographic signature for a block of data.
    /// - Parameters:
    ///   - digest: The digest to sign.
    ///
    /// Example to generate a SHA256 digest and sign with the private key:
    /// ```swift
    /// let key = RSA.Signing.PrivateKey()
    /// let data = SHA256.hash(data: "hello world".data(using: .utf8)!)
    ///
    /// if let signature = try? key.signature(for: data) {
    ///    let result = signature.rawRepresentation.base64UrlEncodedString()
    ///    print(result)
    /// }
    /// ```
    /// - Returns: The digital signature.
    /// - Throws: If there is a failure producing the signature.
    public func signature<D>(for digest: D) throws -> RSA.Signing.RSASignature where D : Digest {
        let algorithm = try SecKeyAlgorithm(digestType: D.self)
        let dataToSign = Data(digest)
        var error: Unmanaged<CFError>?
        let signature = SecKeyCreateSignature(self.key,
                                              algorithm,
                                              dataToSign as CFData,
                                              &error)

        guard let signature = signature else {
           throw error!.takeRetainedValue() as Error
        }
        
        return try RSA.Signing.RSASignature(rawRepresentation: signature as Data)
    }
}

extension RSA.Signing.PublicKey {
    /// Verifies the cryptographic signature of a block of data using a public key. SHA512 is used as the hash function.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify
    ///   - data: The data that was signed.
    ///
    /// Example to validate a SHA256 digest signed with the private key:
    /// ```swift
    /// let key = RSA.Signing.PrivateKey()
    /// let data = SHA256.hash(data: "hello world".data(using: .utf8)!)
    ///
    /// let signature = try key.signature(for: data) {
    /// let result = key.publicKey.isValidSignature(signature, for: data)
    ///
    /// // Prints true
    /// print(result)
    /// ```
    /// - Returns: A Boolean value that’s `true` if the signature is valid for the given data.
    public func isValidSignature<D>(_ signature: RSA.Signing.RSASignature, for data: D) -> Bool where D : DataProtocol {
        return self.isValidSignature(signature, for: SHA512.hash(data: data))
    }
    
    /// Verifies the cryptographic signature of a block of data using a public key and specified algorithm.
    /// - Parameters:
    ///   - signature: The signature to verify
    ///   - digest: The digest that was signed.
    ///
    /// Example to validate a signature signed with the private key:
    /// ```swift
    /// let key = RSA.Signing.PrivateKey()
    /// let data = "hello world".data(using: .utf8)!
    ///
    /// let signature = try key.signature(for: data) {
    /// let result = key.publicKey.isValidSignature(signature, for: data)
    ///
    /// // Prints true
    /// print(result)
    /// ```
    /// - Returns: A Boolean value that’s `true` if the signature is valid for the given data.
    public func isValidSignature<D>(_ signature: RSA.Signing.RSASignature, for digest: D) -> Bool where D : Digest {
        do {
            let algorithm = try SecKeyAlgorithm(digestType: D.self)
            let data = Data(digest)
            var error: Unmanaged<CFError>? = nil
            let result = SecKeyVerifySignature(self.key,
                                               algorithm,
                                               data as CFData,
                                               signature.rawRepresentation as CFData,
                                               &error)
            return result
        }
        catch {
            return false
        }
    }
}

extension RSA.Signing {
    /// A key whose value indicates the number of bits in a cryptographic key.
    public struct KeySize {
        public let bitLength: Int

        /// RSA key size of 2048 bits.
        public static let bits2048 = RSA.Signing.KeySize(bitLength: 2048)

        /// RSA key size of 3072 bits.
        public static let bits3072 = RSA.Signing.KeySize(bitLength: 3072)

        /// RSA key size of 4096 bits.
        public static let bits4096 = RSA.Signing.KeySize(bitLength: 4096)

        /// RSA key size with a custom number of bits.
        ///
        /// - Parameters:
        ///     - bitLength: Positive integer that is a multiple of 8.
        fileprivate init(bitLength: Int) {
            self.bitLength = bitLength
        }
    }
    
    /// A RSA signature.
    public struct RSASignature: ContiguousBytes {
        /// Returns the raw signature.
        public var rawRepresentation: Data

        /// Initializes SHASignature from the raw representation.
        public init<D>(rawRepresentation: D) throws where D : DataProtocol {
            self.rawRepresentation = Data(rawRepresentation)
        }
        
        /// Calls the given closure with a pointer to the underlying bytes of the type’s contiguous storage.
        /// - Parameters:
        ///   - body: A closure with an `UnsafeRawBufferPointer` parameter that points to the contiguous storage for the type. If no such storage exists, the method creates it. If body has a return value, this method also returns that value. The argument is valid only for the duration of the closure’s execution.
        /// - Returns: The return value, if any, of the body closure parameter.
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try self.rawRepresentation.withUnsafeBytes(body)
        }
    }
}

extension SecKeyAlgorithm {
    fileprivate init<D: Digest>(digestType: D.Type = D.self) throws {
        switch digestType {
        case is Insecure.SHA1.Digest.Type:
            self = .rsaSignatureDigestPKCS1v15SHA1
        case is SHA256.Digest.Type:
            self = .rsaSignatureDigestPKCS1v15SHA256
        case is SHA384.Digest.Type:
            self = .rsaSignatureDigestPKCS1v15SHA384
        case is SHA512.Digest.Type:
            self = .rsaSignatureDigestPKCS1v15SHA512
        default:
            throw CryptoKitError.incorrectParameterSize
        }
    }
}

extension Data {
    /// Initializes a Data from a Digest.
    ///  - Parameters:
    ///    - digest: The digest that was signed.
    init<D: Digest>(_ digest: D) {
        self = digest.withUnsafeBytes {
            Data($0)
        }
    }
}

