//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import Foundation

/// The enumerated type that defines extended transaction attributes.
public enum TransactionAttribute: String, Codable, Sendable {
    /// The source IP address that is initiating 2FA.
    /// - remark: This value maps to `originIpAddress` in the transaction payload.
    /// ### Cloud
    /// The `transactionData` will contain the following JSON:
    /// ```swift
    /// {
    ///   "transactionData": {
    ///     "originIpAddress": "192.168.222.222"
    ///   }
    /// }
    /// ```
    /// ### On-premise
    /// The `attributesPending` will contain the following JSON:
    /// ```swift
    /// {
    ///   "attributesPending":[
    ///     {
    ///       "name":"mmfa.request.extras",
    ///       "values":[
    ///         {
    ///           "originIpAddress":"192.168.222.222"
    ///         }
    ///       ]
    ///     }
    ///   ]
    /// }
    /// ```
    case ipAddress

    /// The source location (or estimation) of the real-world geographic location initiating 2FA.
    /// ### Cloud
    /// The `transactionData` will contain the following `additionalData` JSON:
    /// ```swift
    /// {
    ///   "transactionData":{
    ///     "additionalData":[
    ///       {
    ///         "name":"originLocation",
    ///         "value":"Gold Coast, Australia"
    ///       }
    ///     ]
    ///   }
    /// }
    /// ```
    /// ### On-premise
    /// The `attributesPending` will contain the following JSON:
    /// ```swift
    /// {
    ///   "attributesPending":[
    ///     {
    ///       "name":"mmfa.request.extras",
    ///       "values":[
    ///         {
    ///           "originLocation":"Gold Coast, Australia"
    ///         }
    ///       ]
    ///     }
    ///   ]
    /// }
    /// ```
    case location

    /// The image associated with the transaction.
    /// ### Cloud
    /// The `transactionData` will contain the following JSON:
    /// ```swift
    /// {
    ///   "transactionData":{
    ///     "additionalData":[
    ///       {
    ///         "name":"imageURL",
    ///         "value":"http://host.com/image.png"
    ///       }
    ///     ]
    ///   }
    /// }
    /// ```
    /// ### On-premise
    /// The `attributesPending` will contain the following JSON:
    /// ```swift
    /// {
    ///   "attributesPending":[
    ///     {
    ///       "name":"mmfa.request.extras",
    ///       "values":[
    ///         {
    ///           "imageURL":"http://host.com/image.png"
    ///         }
    ///       ]
    ///     }
    ///   ]
    /// }
    /// ```
    case image

    /// The user agent that is initiating 2FA.
    /// ### Cloud
    /// The `transactionData` will contain the following JSON:
    /// ```swift
    /// {
    ///   "transactionData": {
    ///     "originUserAgent": "Internet Explorer"
    ///   }
    /// }
    /// ```
    /// ### On-premise
    /// The `attributesPending` will contain the following JSON:
    /// ```swift
    /// {
    ///   "attributesPending":[
    ///     {
    ///       "name":"mmfa.request.extras",
    ///       "values":[
    ///         {
    ///           "originUserAgent":"Internet Explorer"
    ///         }
    ///       ]
    ///     }
    ///   ]
    /// }
    /// ```
    case userAgent

    /// The defined transaction type.  For example: `Transaction`, `Sign-in` etc.
    /// - remark: The default value is "Request" as a localized string.
    /// ### Cloud
    /// The `transactionData` will contain the following JSON:
    /// ```swift
    /// {
    ///   "transactionData":{
    ///     "additionalData":[
    ///       {
    ///         "name":"type",
    ///         "value":"Transaction"
    ///       }
    ///     ]
    ///   }
    /// }
    /// ```
    /// ### On-premise
    /// The `attributesPending` will contain the following JSON:
    /// ```swift
    /// {
    ///   "attributesPending":[
    ///     {
    ///       "name":"mmfa.request.extras",
    ///       "values":[
    ///         {
    ///           "type":"Transacrtion"
    ///         }
    ///       ]
    ///     }
    ///   ]
    /// }
    /// ```
    case type

    /// An optional correlation setting that the end user will confirm a value.
    /// - remark: Where `correlationValue` is not provided, the value is calculated.
    /// ### Cloud
    /// The `transactionData` will contain the following JSON:
    /// ```swift
    /// {
    ///   "transactionData":{
    ///     "additionalData":[
    ///       {
    ///         "name":"correlationEnabled",
    ///         "value": true
    ///       },
    ///        {
    ///         "name":"correlationValue",
    ///         "value": 12
    ///       }
    ///     ]
    ///   }
    /// }
    /// ```
    /// ### On-premise
    /// The `attributesPending` will contain the following JSON:
    /// ```swift
    /// {
    ///   "attributesPending":[
    ///     {
    ///       "name":"mmfa.request.extras",
    ///       "values":[
    ///         {
    ///           "correlationEnabled": true,
    ///           "correlationValue": 12
    ///         }
    ///       ]
    ///     }
    ///   ]
    /// }
    /// ```
    case correlation
    
    /// Data that is supplied in the transaction payload that was not parsed and assigned to other `TransactionAttributes`.
    /// - remark: The value is represented as an array of JSON `{ "name": "name1", "value": "value1" }`. elements.
    /// ### Cloud
    /// The `transactionData` will contain the following JSON:
    /// ```swift
    /// {
    ///   "transactionData":{
    ///     "additionalData":[
    ///       {
    ///         "name":"Firstname",
    ///         "value":"John"
    ///       },
    ///       {
    ///         "name":"Lastname",
    ///         "value":"Smith"
    ///       }
    ///     ]
    ///   }
    /// }
    /// ```
    /// ### On-premise
    /// The `attributesPending` will contain the following JSON:
    /// ```swift
    /// {
    ///   "attributesPending":[
    ///     {
    ///       "name":"mmfa.request.extras",
    ///       "values":[
    ///         {
    ///           "firstName":"John",
    ///           "lastname":"Smith"
    ///         }
    ///       ]
    ///     }
    ///   ]
    /// }
    /// ```
    case custom
}

/// A structure that contains pending transaction information.
public struct PendingTransactionInfo: Sendable {
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

    /// The name of the identifier to retrive the private key stored during factor enrollment.
    public let keyName: String
    
    /// A value that identifies the specific authentication factor or factor policy.
    public let factorId: String
    
    /// The name indicating the type of authentication factor.
    public let factorType: String

    /// The value to be signed using the private key created during the factor enrollment.
    public let dataToSign: String

    /// The creation timestamp of the transaction.
    ///
    /// The value is assigned in UTC time.
    public let timeStamp: Date

    /// The expiration timestamp of the transaction.
    ///
    /// The value is assigned in UTC time.
    public let expiryTime: Date

    /// Additional contextual attributes.
    public let additionalData: [TransactionAttribute: String]
}

/// Uses the transaction identifier for the purposes of multi-factor fatigue to generate a correlation value.
/// - parameter transactionId: The The identifier of the transaction.
/// - returns: The value of the computation.
/// - remark: Uses the first 32-bits (8 characters) of the transaction identifier as an integer the modulas by 100 to complete the calculation.
internal func computeCorrelationValue(from transactionId: String) -> String {
    // Get the first 8 caharacters
    let value = transactionId.prefix(8)
    let valueAsInt = Int(value, radix: 16)
    return String(format: "%02d", (valueAsInt ?? 0) % 100)
}
