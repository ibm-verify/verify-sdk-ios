//
// Copyright contributors to the IBM Verify Adaptive SDK for iOS project
//

import Foundation

// MARK: Delegate Results

/// A placeholder protocol to represent the result of an assessment operation.
public protocol AdaptiveResult {
}

/// A placeholder protocol to represent the result of an generate operation.
public protocol GenerateResult {
}


// MARK: Adaptive result structures.
/// Represents a deny assessment result.
public struct DenyAssessmentResult: AdaptiveResult {
    /// Initializes a new instance of `DenyAssessmentResult`.
    public init() {
    }
}

/// Represents an allow  assessment result.
public struct AllowAssessmentResult: AdaptiveResult {
    /// JSON string representing an OAuth token.
    public let token: String
    
    /// Initializes a new instance of `AllowAssessmentResult`.
    /// - Parameter token: JSON string representing an OAuth token.
    public init(_ token: String) {
        self.token = token
    }
}

/// Represents an requires assessment result.
public struct RequiresAssessmentResult: AdaptiveResult {
    /// Transaction identifier used to associate an evaluation.
    public let transactionId: String
    
    /// The array of factors the user has enrolled in that can be used for authentication.
    public let factors: [AssessmentFactor]
    
    /// Initializes a new instance of `RequiresAssessmentResult`.
    /// - Parameters:
    ///   - transactionId: Transaction identifier used to associate an evaluation.
    ///   - factors: The array of factors that can be used to generate 2nd-factor evaluation or simple evaluation.
    public init(_ transactionId: String, factors: [AssessmentFactor]) {
        self.transactionId = transactionId
        self.factors = factors
    }
}

// MARK: Generate result structures.

/// The credentials allowed to perform authentication.
/// - Remark: `type` must be 'public-key' for FIDO.  `id` refers to the credential identifier.
public typealias FIDOCredential = (id: String, type: String)

/// Represents a void generate result.
/// - Remark: A `VoidGenerateResult` means the generate operation was successful with no additional data for the consuming client to integrate with.
public struct VoidGenerateResult: GenerateResult {
    /// Initializes a new instance of `VoidGenerateResult`.
    public init() {
    }
}

/// Represents a one-time passcode (OTP) generate result.
public struct OtpGenerateResult: GenerateResult {
    /// The prefix correlation of the an one-time passcode.
    /// - Remark: The prefx example, `1234A`
    public let correlation: String
    
    /// Initializes a new instance of `OtpGenerateResult`.
    /// - Parameter correlation: The prefix correlation of the an one-time passcode.
    public init(_ correlation: String) {
        self.correlation = correlation
    }
}

extension OtpGenerateResult: Decodable {
}

/// Represents Fast Identity Online (FIDO) challenge.
public struct FIDOGenerateResult: GenerateResult {
    /// The identifier of the relying party associated with the FIDO registration.
    public let relyingPartyId: String
    
    /// The unique challenge used as part of this authentication attempt.
    public let challenge: String
    
    /// The extent to which the user must verify.
    /// - Remark: The default value is **preferred**.
    public let userVerification: String?
    
    /// The time for the client to wait for user interaction.
    public let timeout: Int
    
    /// The credentials allowed to perform authentication. Can be empty when performing login without a username.
    public let allowCredentials: [FIDOCredential]?
    
   /// Initializes a new instance of `FIDOGenerateResult`.
    /// - Parameters:
    ///   - relyingPartyId: The identifier of the relying party associated with the FIDO registration.
    ///   - challenge: The challenge to be signed.
    ///   - userVerification: The extent to which the user must verify. Default is `preferred`.
    ///   - timeout: The time for the client to wait for user interaction.
    ///   - allowCredentials: The credentials allowed to perform authentication.
    public init(_ relyingPartyId: String, challenge: String, userVerification: String? = "preferred", timeout: Int, allowCredentials: [FIDOCredential]? = nil) {
        self.relyingPartyId = relyingPartyId
        self.challenge = challenge
        self.userVerification = userVerification
        self.timeout = timeout
        self.allowCredentials = allowCredentials
    }
    
    enum CodingKeys: String, CodingKey {
        case fido
    
        enum FidoCodingKeys: String, CodingKey {
            case relyingPartyId = "rpId"
            case challenge
            case timeout
            case allowCredentials
            case userVerification
        }
    }
}

extension FIDOGenerateResult: Decodable {
    /// Creates a new instance by decoding from the given decoder.
    /// - Parameter decoder: The decoder to read data from.
    /// - Remark: This initializer throws an error if reading from the decoder fails, or if the data read is corrupted or otherwise invalid.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let nestedContainer = try container.nestedContainer(keyedBy: CodingKeys.FidoCodingKeys.self, forKey: .fido)
                
        self.relyingPartyId = try nestedContainer.decode(String.self, forKey: .relyingPartyId)
        self.timeout =  try nestedContainer.decode(Int.self, forKey: .timeout)
        self.challenge = try nestedContainer.decode(String.self, forKey: .challenge)
        self.userVerification = try nestedContainer.decodeIfPresent(String.self, forKey: .userVerification) ?? nil
        
        if let result = try nestedContainer.decodeIfPresent([[String: String]].self, forKey: .allowCredentials) {
            var allowCredentials = [FIDOCredential]()
            
            // Loop through each JSON allowCredentials structure pulling out the values to create the FidoCredentails type.
            for item in result {
                let values = item.values.map{ $0 }
                allowCredentials.append(FIDOCredential(id: values[1], type: values[0]))
            }
            self.allowCredentials = allowCredentials
        }
        else {
            self.allowCredentials = nil
        }
    }
}


/// Represents a key and user friendly question.
public struct QuestionInfo: Decodable {
    /// The key that identifies the question.
    public let questionKey: String
    
    /// The user friendly representation of the question.
    public let question: String
}

/// Represents user generated knowledge queations.
public struct KnowledgeQuestionGenerateResult: GenerateResult {
    /// An array of `QuestionInfo` structures.
    public let questions: [QuestionInfo]
    
    /// Initializes a new instance of `KnowledgeQuestionGenerateResult`.
    /// - Parameter questions: An array of `QuestionInfo` structures.
    public init(_ questions: [QuestionInfo]) {
        self.questions = questions
    }

    enum CodingKeys: String, CodingKey {
        case questions
    }
}

extension KnowledgeQuestionGenerateResult: Decodable {
    /// Creates a new instance by decoding from the given decoder.
    /// - Parameter decoder: The decoder to read data from.
    /// - Remark: This initializer throws an error if reading from the decoder fails, or if the data read is corrupted or otherwise invalid.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        self.questions = try container.decodeIfPresent([QuestionInfo].self, forKey: .questions) ?? []
    }
}


/// Protocol to perform adaptive authenticator operations.
public protocol AdaptiveDelegate {
    /// Executes an assessment against a endpoint that integrates against Cloud Identity Policy Driven Authentication services.
    /// - Parameters:
    ///   - sessionId: The session identifier for the hosting application.
    ///   - evaluationContext: The stage in the application for which to perform an evaluation.
    /// (Used for continuous assessment throughout the application.) Different "stages" or "contexts"
    /// will result in different evaluation results, as configured in the sub-policies of the tenant
    /// application's policy. Possible options are "login", "landing", "profile", "resume", "highassurance", "other".
    ///   - completion: A value that represents either a success or a failure, including an associated `AdaptiveResult` or `Error` in each case.
    func assessment(with sessionId: String, evaluationContext: String, completion: @escaping (Result<AdaptiveResult, Error>) -> Void)
    
    /// Generate a factor against an endpoint that integrates against IBM Verify Policy Driven Authentication services.
    /// - Parameters:
    ///   - enrolmentId: The users enrolment identifier used to associate an evaluation.
    ///   - transactionId: Transaction identifier used to associate an evaluation.
    ///   - factor: A type of factor required to authenticate.
    ///   - completion: A value that represents either a success or a failure, including an associated `GenerateResult` or `Error` in each case.
    func generate(with enrolmentId: String, transactionId: String, factor: FactorType, completion: @escaping (Result<GenerateResult, Error>) -> Void)
    
    /// Evaluates a factor against an endpoint that integrates against Cloud Identity Policy Driven Authentication services.
    /// - Parameters:
    ///   - response: The ``FactorEvaluation`` to expect on evaluation.
    ///   - evaluationContext: The stage in the application for which to perform an evaluation.
    /// (Used for continuous assessment throughout the application.) Different "stages" or "contexts"
    /// will result in different evaluation results, as configured in the sub-policies of the tenant
    /// application's policy. Possible options are "login", "landing", "profile", "resume", "highassurance", "other".
    ///   - completion: A value that represents either a success or a failure, including an associated `AdaptiveResult` or `Error` in each case.
    func evaluate(using response: FactorEvaluation, evaluationContext: String, completion: @escaping (Result<AdaptiveResult, Error>) -> Void)
}
