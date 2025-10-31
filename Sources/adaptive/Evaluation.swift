//
// Copyright contributors to the IBM Verify Adaptive SDK for iOS project
//

import Foundation

/// A placeholder protocol to represent a factor evaluation.
public protocol FactorEvaluation {
    /// Transaction identifier used to associate an evaluation.
    var transactionId: String { get }
}

/// Represents a username and password for evaluation.
public struct UsernamePasswordEvaluation: FactorEvaluation {
    /// Transaction identifier used to associate an evaluation.
    public let transactionId: String
    
    /// The username used for evaluation.
    public let username: String
    
    /// The associated password for the username.
    public let password: String
    
    /// Initializes a new instance of `UsernamePasswordEvaluation`.
    /// - Parameters:
    ///   - transactionId: Transaction identifier used to associate an evaluation.
    ///   - username: The username used for evaluation.
    ///   - password: The associated password for the username.
    public init(_ transactionId: String, username: String, password: String) {
        self.transactionId = transactionId
        self.username = username
        self.password = password
   }
}

/// Represents a one-time passcode for an evaluation.
public struct OneTimePasscodeEvaluation: FactorEvaluation {
    /// Transaction identifier used to associate an evaluation.
    public let transactionId: String
    
    /// The code generated from the seed.
    public let code: String
    
    /// The type of one-time passcode.
    public let otp: OneTimePasscodeType
    
    /// Initializes a new instance of `OneTimePasscodeEvaluation`.
    /// - Parameters:
    ///   - transactionId: Transaction identifier used to associate an evaluation.
    ///   - code: The code generated from the seed.
    ///   - otp: The type of one-time passcode.
    public init(_ transactionId: String, code: String, otp: OneTimePasscodeType) {
        self.transactionId = transactionId
        self.code = code
        self.otp = otp
    }
}

 /// Represents a Fast Identity Online (FIDO) evaluation.
 /// - Remark: Refer to [Web Authentication: An API for accessing Public Key Credentials Level 2](https://www.w3.org/TR/webauthn-2/) for full documentation of FIDO W3C recommendation.
 public struct FIDOEvaluation: FactorEvaluation {
    /// Transaction identifier used to associate an evaluation.
    public let transactionId: String
     
    /// A base64Url-encoded `clientDataJson` that was received from the WebAuthn client.
    public let clientDataJSON: String
     
    /// The information about the authentication produced by the authenticator and verified by the signature.
    public let authenticatorData: String
    
    /// The identifier for the user who owns this authenticator.  It identifies the user to be logged in.
    public let userHandle: String?
    
    /// The base64Url-encoded bytes of the signature of the challenge data that was produced by the authenticator.
    public let signature: String
     
    /// Initializes a new instance of `OneTimePasscodeEvaluation`.
    /// - Parameters:
    ///   - transactionId: Transaction identifier used to associate an evaluation.
    ///   - clientDataJSON: A base64Url-encoded `clientDataJson` that was received from the WebAuthn client.
    ///   - authenticatorData: The information about the authentication produced by the authenticator and verified by the signature.
    ///   - userHandle: The identifier for the user who owns this authenticator.  It identifies the user to be logged in.
    ///   - signature: The base64Url-encoded bytes of the signature of the challenge data that was produced by the authenticator.
    public init(_ transactionId: String, clientDataJSON: String, authenticatorData: String, userHandle: String? = nil, signature: String) {
        self.transactionId = transactionId
        self.clientDataJSON = clientDataJSON
        self.authenticatorData = authenticatorData
        self.userHandle = userHandle
        self.signature = signature
     }
}
 
/// Represents a QR code evaluation.
public struct QrCodeEvaluation: FactorEvaluation {
    /// Transaction identifier used to associate an evaluation.
    public let transactionId: String
    
    /// The access token associated with user.
    public let accessToken: String
    
    /// Initializes a new instance of `OneTimePasscodeEvaluation`.
    /// - Parameters:
    ///   - transactionId: Transaction identifier used to associate an evaluation.
    ///   - accessToken: The access token associated with user.
    public init(_ transactionId: String, accessToken: String) {
        self.transactionId = transactionId
        self.accessToken = accessToken
    }
}
 
/// Represents a list of knowledge question answers.
public struct KnowledgeQuestionEvaluation: FactorEvaluation {
    /// Transaction identifier used to associate an evaluation.
    public let transactionId: String

    /// The dictionary of question keys and associated answers.
    /// - Remark: An knowledge question evaluation requires the key to be unique. For example:
    /// ```
    /// "questions": [{
    ///    "questionKey": "firstHouseStreet",
    ///    "question": "What was the street name of the first house you ever lived in?"
    /// },
    /// {
    ///    "questionKey": "bestFriend",
    ///    "question": "What is the first name of your best friend?"
    /// }]
    /// ```
    /// The `questionKey` would represent the key in the dictionary, with the value represented by the answers.
    public let answers: [String: String]
     
     /// Initializes a new instance of `OneTimePasscodeEvaluation`.
     /// - Parameters:
     ///   - transactionId: Transaction identifier used to associate an evaluation.
     ///   - answers: The dictionary of question keys and associated answers.
    public init(_ transactionId: String, answers: [String: String]) {
        self.transactionId = transactionId
        self.answers = answers
    }
}
