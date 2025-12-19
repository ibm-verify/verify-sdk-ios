//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import Foundation
import CryptoKit

/// The authenticator for managing one-time passcodes (OTP), supporting both TOTP and HOTP formats.
public class OTPAuthenticator: AuthenticatorDescriptor {
    // MARK: - Properties

    /// Unique identifier for the authenticator instance.
    public let id: String

    /// Name of the service (e.g., "Google", "GitHub").
    public let serviceName: String

    /// Name of the account associated with the service (e.g., "user@example.com").
    public var accountName: String

    /// Time-based OTP factor, if applicable.
    public let totp: TOTPFactorInfo?

    /// Counter-based OTP factor, if applicable.
    public let hotp: HOTPFactorInfo?

    // MARK: - Codable Support

    /// Keys used for encoding and decoding JSON.
    private enum CodingKeys: String, CodingKey {
        case id
        case serviceName
        case accountName
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
    ///   - factor: An instance of ``HOTPFactorInfo`` or ``TOTPFactorInfo``
    public init(with serviceName: String, accountName: String, factor: some Factor) {
        precondition(factor is HOTPFactorInfo || factor is TOTPFactorInfo, "Only TOTP and HOTP factors are allowed.")
        
        self.id = UUID().uuidString
        self.serviceName = serviceName
        self.accountName = accountName

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

    /// Convenience initializer that parses an OTP URI from a QR code scan.
    /// - Parameter value: The URI string scanned from a QR code.
    /// - Returns: A configured `OTPAuthenticator` instance or `nil` if parsing fails.
    public required convenience init?(fromQRScan value: String) {
        guard let url = URL(string: value),
              url.scheme == "otpauth",
              let type = OTPType(rawValue: url.host ?? ""),
              let rawLabel = url.pathComponents.dropFirst().joined(separator: "/").removingPercentEncoding,
              let components = URLComponents(string: value),
              let queryItems = components.queryItems else {
            return nil
        }

        // Extract query parameters
        var secret: String?
        var issuer: String?
        var algorithm: SigningAlgorithm = .sha1
        var digits: Int = 6
        var period: Int? = 30
        var counter: Int? = 1

        for item in queryItems {
            switch item.name.lowercased() {
            case "secret":
                secret = item.value
            case "issuer":
                issuer = item.value?.removingPercentEncoding
            case "algorithm":
                if let value = item.value, let signingAlgorithm = SigningAlgorithm(from: value) {
                    algorithm = signingAlgorithm
                } else {
                    return nil // Invalid algorithm
                }
            case "digits":
                if let value = item.value, let intVal = Int(value), [6, 8].contains(intVal) {
                    digits = intVal
                } else {
                    return nil // Invalid digits
                }
            case "period":
                if let value = item.value, let intVal = Int(value) {
                    period = intVal
                }
            case "counter":
                if let value = item.value, let intVal = Int(value) {
                    counter = intVal
                }
            default:
                continue
            }
        }

        // Ensure at least one identifier is present
        if rawLabel.isEmpty && issuer == nil {
            return nil // No label or issuer to use as account/service name
        }
        
        guard let secretUnwrapped = secret else {
            return nil
        }

        // Validate period for TOTP
        if type == .totp {
            guard let periodUnwrapped = period, (10...300).contains(periodUnwrapped) else {
                return nil
            }
            period = periodUnwrapped
        }

        // Determine account name from label and issuer
        var accountName: String = rawLabel
        if let issuer = issuer {
            if rawLabel.contains(":") {
                let parts = rawLabel.split(separator: ":", maxSplits: 1).map { String($0) }
                if parts.count == 2 && parts[0] == issuer {
                    accountName = parts[1]
                }
            } else {
                // No account name in label, use issuer as fallback
                accountName = issuer
            }
        }

        // Use issuer as service name (or fallback to accountName if issuer is nil)
        let serviceName = issuer ?? accountName

        switch type {
        case .totp:
            self.init(
                with: serviceName,
                accountName: accountName,
                factor: TOTPFactorInfo(
                    with: secretUnwrapped,
                    digits: digits,
                    algorithm: algorithm,
                    period: period ?? 30
                )
            )
        case .hotp:
            self.init(
                with: serviceName,
                accountName: accountName,
                factor: HOTPFactorInfo(
                    with: secretUnwrapped,
                    digits: digits,
                    algorithm: algorithm,
                    counter: counter ?? 1
                )
            )
        }
    }

    /// Decodes an instance from a decoder (e.g., from JSON).
    /// - Parameter decoder: The decoder to read data from.
    public required init(from decoder: Decoder) throws {
        let rootContainer = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try rootContainer.decode(String.self, forKey: .id)
        self.serviceName = try rootContainer.decode(String.self, forKey: .serviceName)
        self.accountName = try rootContainer.decode(String.self, forKey: .accountName)
        self.totp = try rootContainer.decodeIfPresent(TOTPFactorInfo.self, forKey: .totp)
        self.hotp = try rootContainer.decodeIfPresent(HOTPFactorInfo.self, forKey: .hotp)
    }

    /// Encodes the instance into an encoder (e.g., for JSON serialization).
    /// - Parameter encoder: The encoder to write data to.
    public func encode(to encoder: Encoder) throws {
        var rootContainer = encoder.container(keyedBy: CodingKeys.self)
        try rootContainer.encode(self.id, forKey: .id)
        try rootContainer.encode(self.serviceName, forKey: .serviceName)
        try rootContainer.encode(self.accountName, forKey: .accountName)
        try rootContainer.encodeIfPresent(self.totp, forKey: .totp)
        try rootContainer.encodeIfPresent(self.hotp, forKey: .hotp)
    }
}
