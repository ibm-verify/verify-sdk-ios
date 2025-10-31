//
// Copyright contributors to the IBM Verify Adaptive SDK for iOS project
//

import Foundation

/// The **AssessmentFactor** is used by `AllowFactor` and `EnrolledFactor` structures to represent the type of factor returned from the `AdaptiveResult`.
public protocol AssessmentFactor: Decodable {
    /// The type of factor.
    var type: FactorType {
        get
    }
}

/// The `AllowedFactor` represents a first factor assessment.
public struct AllowedFactor: AssessmentFactor {
    /// The type of factor.
    public var type: FactorType

    enum CodingKeys: String, CodingKey {
       case type
   }
}

extension AllowedFactor: Decodable {
    /// Creates a new instance by decoding from the given decoder.
    /// - Parameter decoder: The decoder to read data from.
    /// - Remark: This initializer throws an error if reading from the decoder fails, or if the data read is corrupted or otherwise invalid.
    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)

        // Convert the factor as a string into an FactorType enum.
        type = try values.decodeIfPresent(FactorType.self, forKey: .type) ?? .unknown
    }
}

/// Represents a structure that defines an enrolled factor.  An enrolled factor is used to generate a 2nd-factor assessment.
public struct EnrolledFactor: AssessmentFactor {
    /// The type of factor enrolment.
    public var type: FactorType
    
    /// The unique identifer of the enrolment.
    /// - Remark: This value is typically a *GUID*.
    public var id: String
    
    /// A flag to indicate the enrolment is enabled.
    public var enabled: Bool? = nil
    
    /// A flag to indicate if the enrolment has been validated.
    /// - Remark: Enrolled factor that have not been validate may be rejected in an assessment operation.
    public var validated: Bool? = nil
    
    /// A dictionary of attributes about the enrolled factor.
    public var attributes: [String: Any]
    
    enum CodingKeys: String, CodingKey {
        case id
        case type
        case enabled
        case validated
        case attributes
    }
}

extension EnrolledFactor: Decodable {
    /// Creates a new instance by decoding from the given decoder.
    /// - Parameter decoder: The decoder to read data from.
    /// - Remark: This initializer throws an error if reading from the decoder fails, or if the data read is corrupted or otherwise invalid.
    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decode(String.self, forKey: .id)
        type = try values.decode(FactorType.self, forKey: .type)
        enabled = try values.decodeIfPresent(Bool.self, forKey: .enabled)
        validated = try values.decodeIfPresent(Bool.self, forKey: .validated)
        
        // Generate the additional attributes associated with the enrolment.
        attributes = try values.decode([String: Any].self, forKey: .attributes)
    }
}
