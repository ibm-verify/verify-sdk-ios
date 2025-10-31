//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import Foundation
import CryptoKit

/// The authenticator for managing one-time passcodes.
public class OTPAuthenticator: AuthenticatorDescriptor {
    public let id: String
    public let serviceName: String
    public var accountName: String
    
    /// A list of allowed factors the user can attempt to perform 2nd factor (2FA) and multi-factor authentication (MFA).
    /// 
    /// - remark: The allowed factors are restricted to ``HOTPFactorInfo`` or ``TOTPFactorInfo``
    public let allowedFactors: [FactorType]
    
    /// The root level JSON structure for decoding.
    private enum CodingKeys: String, CodingKey {
        case id
        case serviceName
        case accountName
        case allowedFactors
    }
    
    /// Initializes the authenticator to use a hash-based message authentication.
    /// - Parameters:
    ///   - serviceName: The name of the service providing the one-time passcode.
    ///   - accountName: The name of the account associated with the service.
    ///   - factor: An instance of ``HOTPFactorInfo`` or ``TOTPFactorInfo``
    public init(with serviceName: String, accountName: String, factor: some Factor) {
        precondition(factor is HOTPFactorInfo || factor is TOTPFactorInfo, "Only TOTP and HOTP factors are allowed.")
        
        self.id = UUID().uuidString
        self.serviceName = serviceName
        self.accountName = accountName
        
        if let value = factor as? HOTPFactorInfo {
            self.allowedFactors = [
                .hotp(value)
            ]
        }
        else if let value = factor as? TOTPFactorInfo {
            self.allowedFactors = [
                .totp(value)
            ]
        }
        else {
            self.allowedFactors = []
        }
    }
    
    /// Initializes the authenticator to use a one-time passcode determined by the result of a QR code scan.
    /// - Parameters:
    ///   - value: The string value resulting from the QR code scan.
    ///
    /// The URI format of a one-time passcode is represented as:
    /// `otpauth://totp/Example:alice@host.com?secret=JBSWY3DPEHPK3PXP&issuer=Example`
    ///
    /// Additional parameters `period`, `digits` and `algorithm` can also be included in the URI string.
    public init?(fromQRScan value: String) {
        var dictionary: [String: String] = [:]
        let pattern = "otpauth://([ht]otp)/([^\\?]+)\\?(.*)"
        let regex = try! NSRegularExpression(pattern: pattern, options: [])

        guard let match = regex.firstMatch(in: value, options: [], range: NSMakeRange(0, value.count)) else {
            return nil
        }

        // Step 1: - Match the OTP type
        guard let type = EnrollableType(rawValue: (value as NSString).substring(with: match.range(at: 1))) else {
            return nil
        }
       
        //  Step 2: - Match the issuer or the issuer:username
        guard let label = (value as NSString).substring(with: match.range(at: 2)).removingPercentEncoding else {
           return nil
        }

        let fields = label.split(separator: ":").map(String.init)
        self.serviceName = fields[0]
        
        if fields.count > 1 {
            self.accountName = fields.dropFirst().joined(separator: ":").trimmingCharacters(in: .whitespacesAndNewlines)
        }
        else {
            self.accountName = fields[0]
        }

        // Step 3: - Parse the additional query params
        let parameters = (value as NSString).substring(with: match.range(at: 3)).split(separator: "&")

        for parameter in parameters {
            let pair = parameter.split(separator: "=").map(String.init)
            if pair.count == 2 {
                dictionary[pair[0]] = pair[1].removingPercentEncoding
            }
        }
        
        // Step 4: - Assign the mandatory secret, algorithm and digits values
        guard let secret = dictionary["secret"] else {
            return nil
        }
        
        guard let algorithm = HashAlgorithmType(rawValue: dictionary["algorithm"] ?? "sha1") else {
            return nil
        }

        guard let digits = Int(dictionary["digits"] ?? "6"), (digits == 6 || digits == 8) else {
            return nil
        }
        
        // Step 5: - Assign the optional period or counter values based on the type
        var value: Int?
        if type == .hotp, let counter = Int(dictionary["counter"] ?? "1") {
            value = counter
        }

        // For TOTP the supported period intervals are between 10 and 300.
        if type == .totp, let period = Int(dictionary["period"] ?? "30"), period >= 10, period <= 300 {
            value = period
        }
        
        // Ensure a period or counter value has been assigned
        guard let value = value else {
            return nil
        }
        
        // Step 6: - Create the OTP factor and add to allowedMethods array.
        switch type {
        case .totp:
            self.allowedFactors = [
                .totp(TOTPFactorInfo(with: secret, digits: digits, algorithm: algorithm, period: value))
            ]
        case .hotp:
            self.allowedFactors = [
                .hotp(HOTPFactorInfo(with: secret, digits: digits, algorithm: algorithm, counter: value))
            ]
        default:
            return nil
        }
        
        // Step 6: - Assign an identifier
        self.id = UUID().uuidString
    }
    
    /// Creates a new instance by decoding from the given decoder
    /// - Parameters:
    ///   - decoder: The decoder to read data from.
    public required init(from decoder: Decoder) throws {
        let rootContainer = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try rootContainer.decode(String.self, forKey: .id)
        self.serviceName = try rootContainer.decode(String.self, forKey: .serviceName)
        self.accountName = try rootContainer.decode(String.self, forKey: .accountName)
        self.allowedFactors = try rootContainer.decode([FactorType].self, forKey: .allowedFactors)
    }

    /// Encodes this value into the given encoder.
    /// - parameter encoder: The encoder to write data to.
    public func encode(to encoder: Encoder) throws {
        var rootContainer = encoder.container(keyedBy: CodingKeys.self)
        try rootContainer.encode(self.id, forKey: .id)
        try rootContainer.encode(self.serviceName, forKey: .serviceName)
        try rootContainer.encode(self.accountName, forKey: .accountName)
        try rootContainer.encode(self.allowedFactors, forKey: .allowedFactors)
    }
}
