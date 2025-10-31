//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import Foundation

/// The enumerated type that defines extended transaction attributes.
public enum TransactionAttribute: String, Codable {
    /// The source IP address that is initiating 2FA.
    ///
    /// This value maps to `originIpAddress` in the transaction payload.
    case ipAddress

    /// The source location (or estimation) of the real-world geographic location initiating transaction.
    case location

    /// The image associated with the transaction.
    case image

    /// The user agent initiating the transaction.
    case userAgent

    /// The defined transaction type.  For example: `Transaction`, `Sign-in` etc.
    ///
    /// The default value is "Request" as a localized string.
    case type

    /// Data that is supplied in the transaction payload that was not parsed and assigned to other `TransactionAttributes`.
    ///
    /// The value is represented as an JSON array for example:
    ///
    /// ```swift
    /// [{
    ///   "name": "name1",
    ///   "value": "value1"
    /// }]
    /// ```
    case custom
}

/// A structure that contains pending transaction information.
public struct PendingTransactionInfo {
    /// The identifier of the transaction.
    ///
    /// The `id` is represented as a Universal Unique Identifier (UUID).
    public let id: String

    /// The shorten transaction identifier.
    ///
    /// This field returns the characters to the first dash.  Example ab88741b.
    public var shortId: String {
        let index = id.firstIndex(of: "-")!
        return String(id[..<index])
    }

    /// The context message sent in the push notification.
    ///
    /// This message is displayed as the notification message when it arrives at the device.
    /// - remark: This message should not contain any sensitve information.
    public let message: String

    /// The location of the endpoint to complete the transaction operation.
    public let postbackUri: URL

    /// An identifier generated during enrollment to uniquely identify a specific authentication factor.
    public let factorID: UUID
    
    /// The name indicating the type of authentication factor.
    public let factorType: String

    /// The value to be signed using the private key created during the factor enrollment.
    public let dataToSign: String

    /// The creation timestamp of the transaction.
    ///
    /// The value is assigned in UTC time.
    public let timeStamp: Date

    /// Additional contextual attributes.
    public let additionalData: [TransactionAttribute: String]
}
