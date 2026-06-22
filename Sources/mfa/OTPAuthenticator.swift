//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import Foundation
import CryptoKit

/// A thread-safe, secure token manager that represents a standard One-Time Password (OTP) authentication factor.
///
/// This component stores structural account properties and manages cryptographically active counter-based (`HOTP`) or time-based (`TOTP`) factor payload definitions. It conforms to `Sendable` to safely navigate concurrent context bounds.
///
/// ### Compile-Time Type Enforcement
/// Rather than utilizing generic type parameter bounds evaluated at runtime with a `precondition`, this type leverages strict API initialisation overloading. This pattern intercepts type evaluation during compilation, guaranteeing that an instance cannot be constructed with unsupported factors.
public struct OTPAuthenticator: AuthenticatorDescriptor, Sendable {
    // MARK: - Structural Identity Properties

    /// Unique identifier assigned to this specific authenticator instance.
    public let id: String

    /// Name of the service provider issuing the security payload (e.g., "GitHub", "Google").
    public var serviceName: String

    /// User identity identifier or email address linked to the provider token (e.g., "user@example.com").
    public var accountName: String
    
    /// Optional metadata timestamp capturing exactly when this authenticator structure was provisioned.
    public let createdDate: Date?

    // MARK: - Mutually Exclusive Factor Payloads

    /// The active Time-Based One-Time Password parameters (`RFC 6238`), if applicable to this token.
    public let totp: TOTPFactorInfo?

    /// The active HMAC/Counter-Based One-Time Password parameters (`RFC 4226`), if applicable to this token.
    public var hotp: HOTPFactorInfo?

    // MARK: - Codable Structure Mapping

    /// Keys used to map structural properties directly into JSON or serialization payloads.
    private enum CodingKeys: String, CodingKey {
        case id
        case serviceName
        case accountName
        case createdDate
        case totp
        case hotp
    }

    /// Internal classification key defining the targeted OTP operational protocol.
    private enum OTPType: String {
        /// Time-based verification model strategy indicator.
        case totp
        /// Counter/Event-driven verification model strategy indicator.
        case hotp
    }

    // MARK: - Public Compile-Time Safe Initializers

    /// Initializes an authenticator instance explicitly configured with a Counter-Based OTP factor (`HOTP`).
    ///
    /// - Parameters:
    ///   - serviceName: The name of the service platform issuing the token.
    ///   - accountName: The name of the account profile context.
    ///   - createdDate: An optional generation timestamp. Defaults to `nil`.
    ///   - factor: A strict `HOTPFactorInfo` structural context package.
    public init(
        with serviceName: String,
        accountName: String,
        createdDate: Date? = nil,
        factor: HOTPFactorInfo
    ) {
        self.init(
            id: UUID().uuidString,
            serviceName: serviceName,
            accountName: accountName,
            createdDate: createdDate,
            totp: nil,
            hotp: factor
        )
    }

    /// Initializes an authenticator instance explicitly configured with a Time-Based OTP factor (`TOTP`).
    ///
    /// - Parameters:
    ///   - serviceName: The name of the service platform issuing the token.
    ///   - accountName: The name of the account profile context.
    ///   - createdDate: An optional generation timestamp. Defaults to `nil`.
    ///   - factor: A strict `TOTPFactorInfo` structural context package.
    public init(
        with serviceName: String,
        accountName: String,
        createdDate: Date? = nil,
        factor: TOTPFactorInfo
    ) {
        self.init(
            id: UUID().uuidString,
            serviceName: serviceName,
            accountName: accountName,
            createdDate: createdDate,
            totp: factor,
            hotp: nil
        )
    }

    // MARK: - Private Designated Core Initializer

    /// The master designated pipeline initializer that maps explicit structural allocations to state storage properties.
    private init(
        id: String,
        serviceName: String,
        accountName: String,
        createdDate: Date?,
        totp: TOTPFactorInfo?,
        hotp: HOTPFactorInfo?
    ) {
        self.id = id
        self.serviceName = serviceName
        self.accountName = accountName
        self.createdDate = createdDate
        self.totp = totp
        self.hotp = hotp
    }

    // MARK: - Convenience String URI QR Parser

    /// Convenience initializer that safely parses standard `otpauth://` URI schema parameters typically embedded inside QR setup targets.
    ///
    /// Follows the operational semantics defined by Google Authenticator's URI format specification.
    ///
    /// - Parameter value: A raw text string harvested via a camera QR matrix decoding engine scan.
    /// - Returns: An fully operational `OTPAuthenticator` configuration instance, or `nil` if formatting constraints fail verification steps.
    public init?(fromQRScan value: String) {
        // MARK: Isolated Extraction Pipeline Closure
        let parse: (String) -> (
            type: OTPType,
            issuer: String,
            account: String,
            secret: String,
            algorithm: SigningAlgorithm,
            digits: Int,
            period: Int,
            counter: Int
        )? = { input in

            // 1. Structural Schema Validation Bounds Check
            guard
                let components = URLComponents(string: input),
                components.scheme?.lowercased() == "otpauth",
                let type = components.host.flatMap({ OTPType(rawValue: $0.lowercased()) })
            else {
                return nil
            }

            // 2. Query Item Parameter Map Normalization
            let params = components.queryItems?.reduce(into: [String: String]()) {
                $0[$1.name.lowercased()] = $1.value
            } ?? [:]

            // 3. Verification Cryptographic Crypt Key Extract
            guard let secret = params["secret"], !secret.isEmpty else {
                return nil
            }

            // 4. Extract Path Label Payload Identity Attributes
            let decodedLabel: String = {
                let path = components.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
                return path.removingPercentEncoding ?? ""
            }()

            // 5. Parse Composite Label Properties into Separate Components
            let (labelIssuer, labelAccount): (String?, String) = {
                let parts = decodedLabel
                    .split(separator: ":", maxSplits: 1)
                    .map { $0.trimmingCharacters(in: .whitespaces) }

                return parts.count == 2
                    ? (parts[0], parts[1])
                    : (nil, decodedLabel)
            }()

            // 6. Identity Resolution Priority Evaluation Rule
            let issuer = (params["issuer"] ?? labelIssuer ?? "Unknown")
                .trimmingCharacters(in: .whitespaces)

            let account = labelAccount.trimmingCharacters(in: .whitespaces)

            // 7. Extract Support Options with Safe Fallback Defaults
            let algorithm = SigningAlgorithm(from: params["algorithm"] ?? "sha1") ?? .sha1
            let digits = params["digits"].flatMap(Int.init) ?? 6
            let period = params["period"].flatMap(Int.init) ?? 30
            let counter = params["counter"].flatMap(Int.init) ?? 0

            // 8. Design Constraint Metric Guard Check
            guard digits == 6 || digits == 8 else {
                return nil
            }
            
            return (type, issuer, account, secret, algorithm, digits, period, counter)
        }

        // MARK: Pipeline Evaluation and Factor Direct Assignment
        guard let parsed = parse(value) else { return nil }

        switch parsed.type {
        case .totp:
            // TOTP specifications restrict execution windows to manageable limits
            guard (10...300).contains(parsed.period) else { return nil }
            
            // Invokes the compiler-verified TOTP initializer pathway natively without casting parameters
            self.init(
                with: parsed.issuer,
                accountName: parsed.account,
                createdDate: Date(),
                factor: TOTPFactorInfo(
                    with: parsed.secret,
                    digits: parsed.digits,
                    algorithm: parsed.algorithm,
                    period: parsed.period
                )
            )
        case .hotp:
            // Invokes the compiler-verified HOTP initializer pathway natively without casting parameters
            self.init(
                with: parsed.issuer,
                accountName: parsed.account,
                createdDate: Date(),
                factor: HOTPFactorInfo(
                    with: parsed.secret,
                    digits: parsed.digits,
                    algorithm: parsed.algorithm,
                    counter: parsed.counter
                )
            )
        }
    }

    // MARK: - Decentralized Decodable Serialization

    /// Decodes an encapsulated storage configuration matrix block back into a valid dynamic `OTPAuthenticator` record instance.
    ///
    /// - Parameter decoder: The runtime input storage decoding abstraction container target.
    /// - Throws: An explicit `DecodingError` verification crash if property dependencies break structural validation mapping patterns.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try container.decode(String.self, forKey: .id)
        self.serviceName = try container.decode(String.self, forKey: .serviceName)
        self.accountName = try container.decode(String.self, forKey: .accountName)
        self.createdDate = try container.decodeIfPresent(Date.self, forKey: .createdDate)
        self.totp = try container.decodeIfPresent(TOTPFactorInfo.self, forKey: .totp)
        self.hotp = try container.decodeIfPresent(HOTPFactorInfo.self, forKey: .hotp)
    }

    /// Encodes this authentication factor structure safely into an isolated persistent payload destination stream.
    ///
    /// - Parameter encoder: The targeted execution storage serialization system engine layer.
    /// - Throws: An explicit encoding exception type error if dynamic fields fail schema constraint validations.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(serviceName, forKey: .serviceName)
        try container.encode(accountName, forKey: .accountName)
        try container.encodeIfPresent(createdDate, forKey: .createdDate)
        try container.encodeIfPresent(totp, forKey: .totp)
        try container.encodeIfPresent(hotp, forKey: .hotp)
    }
}
