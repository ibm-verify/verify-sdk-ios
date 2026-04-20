//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import Foundation
import CryptoKit

/// The authenticator for managing one-time passcodes (OTP), supporting both TOTP and HOTP formats.
public struct OTPAuthenticator: AuthenticatorDescriptor, Sendable {
    // MARK: - Properties

    /// Unique identifier for the authenticator instance.
    public let id: String

    /// Name of the service (e.g., "Google", "GitHub").
    public var serviceName: String

    /// Name of the account associated with the service (e.g., "user@example.com").
    public var accountName: String
    
    public let createdDate: Date?

    /// Time-based OTP factor, if applicable.
    public let totp: TOTPFactorInfo?

    /// Counter-based OTP factor, if applicable.
    public var hotp: HOTPFactorInfo?

    // MARK: - Codable Support

    /// Keys used for encoding and decoding JSON.
    private enum CodingKeys: String, CodingKey {
        case id
        case serviceName
        case accountName
        case createdDate
        case totp
        case hotp
    }

    /// Enum to distinguish between OTP types.
    private enum OTPType: String {
        case totp
        case hotp
    }

    // MARK: - Initializers

    /// Initializes the authenticator with a specific OTP factor.
    /// - Parameters:
    ///   - serviceName: The name of the service providing the one-time passcode.
    ///   - accountName: The name of the account associated with the service.
    ///   - createdDate: The date the authenticator was created.
    ///   - factor: An instance of ``HOTPFactorInfo`` or ``TOTPFactorInfo``
    public init(with serviceName: String, accountName: String, createdDate: Date? = nil, factor: some Factor) {
        precondition(factor is HOTPFactorInfo || factor is TOTPFactorInfo, "Only TOTP and HOTP factors are allowed.")
        
        self.id = UUID().uuidString
        self.serviceName = serviceName
        self.accountName = accountName
        self.createdDate = createdDate

        // Assign the correct factor type and nil the other.
        switch factor {
        case let hotp as HOTPFactorInfo:
            self.hotp = hotp
            self.totp = nil
        case let totp as TOTPFactorInfo:
            self.totp = totp
            self.hotp = nil
        default:
            fatalError()
        }
    }

    /// Convenience initializer that parses an OTP URI from a standard `otpauth://` QR scan string.
    /// - Parameter value: The URI string scanned from a QR code.
    /// - Returns: A configured `OTPAuthenticator` instance or `nil` if parsing fails.
    public init?(fromQRScan value: String) {
        // MARK: - Parsing Pipeline
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

            // 1. URL + Type Validation
            guard
                let components = URLComponents(string: input),
                components.scheme?.lowercased() == "otpauth",
                let type = components.host.flatMap({ OTPType(rawValue: $0.lowercased()) })
            else {
                return nil
            }

            // 2. Query params (Normalized to lowercase keys)
            let params = components.queryItems?.reduce(into: [String: String]()) {
                $0[$1.name.lowercased()] = $1.value
            } ?? [:]

            // 3. Required: Secret (Base32 encoded)
            guard let secret = params["secret"], !secret.isEmpty else {
                return nil
            }

            // 4. Decode Label (Path)
            // We strip the leading slash and decode percent-encoding.
            let decodedLabel: String = {
                let path = components.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
                return path.removingPercentEncoding ?? ""
            }()

            // 5. Split Label into Issuer and Account
            // Following spec: /Issuer:Account. If no colon, issuer is nil.
            let (labelIssuer, labelAccount): (String?, String) = {
                let parts = decodedLabel
                    .split(separator: ":", maxSplits: 1)
                    .map { $0.trimmingCharacters(in: .whitespaces) }

                return parts.count == 2
                    ? (parts[0], parts[1])
                    : (nil, decodedLabel)
            }()

            // 6. Resolve Final Identities
            // Priority: Query param "issuer" > Label prefix > "Unknown"
            let issuer = (params["issuer"] ?? labelIssuer ?? "Unknown")
                .trimmingCharacters(in: .whitespaces)

            // Account is now strictly whatever was after the colon (or the whole label if no colon)
            let account = labelAccount.trimmingCharacters(in: .whitespaces)

            // 7. Extract Parameters with Defaults
            let algorithm = SigningAlgorithm(from: params["algorithm"] ?? "sha1") ?? .sha1
            let digits = params["digits"].flatMap(Int.init) ?? 6
            let period = params["period"].flatMap(Int.init) ?? 30
            let counter = params["counter"].flatMap(Int.init) ?? 0

            // Enforce valid digit lengths
            guard digits == 6 || digits == 8 else {
                return nil
            }
            
            return (type, issuer, account, secret, algorithm, digits, period, counter)
        }

        // MARK: - Execution & Construction
        guard let parsed = parse(value) else { return nil }

        switch parsed.type {
        case .totp:
            guard (10...300).contains(parsed.period) else { return nil }
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

    /// Decodes an instance from a decoder (e.g., from JSON).
    /// - Parameter decoder: The decoder to read data from.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try container.decode(String.self, forKey: .id)
        self.serviceName = try container.decode(String.self, forKey: .serviceName)
        self.accountName = try container.decode(String.self, forKey: .accountName)
        self.createdDate = try container.decodeIfPresent(Date.self, forKey: .createdDate)
        self.totp = try container.decodeIfPresent(TOTPFactorInfo.self, forKey: .totp)
        self.hotp = try container.decodeIfPresent(HOTPFactorInfo.self, forKey: .hotp)
    }

    /// Encodes the instance into an encoder (e.g., for JSON serialization).
    /// - Parameter encoder: The encoder to write data to.
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
