//
// Copyright contributors to the IBM Verify Adaptive SDK for iOS project
//

import Foundation
@testable import Adaptive

let mockCollectionService = MockCollectionService()

/// A convenience enum to support different adaptive tests.
enum MockAdaptiveTestType : Int {
    case allow = 0
    case deny
    case requiresEnrolled
    case requiresAllowed
    case random
}

/// A mock result.
struct MockAdaptiveServiceResult: Decodable {
    var status: String
    var token: String?
    var factors: [AssessmentFactor]?
    var transactionId: String?
    
    /// The root level JSON structure for decoding.
    private enum CodingKeys: String, CodingKey {
        case status
        case token
        case allowedFactors
        case enrolledFactors
        case transactionId
    }

    /// Creates a new instance by decoding from the given decoder
    /// - parameter decoder: The decoder to read data from.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        // Status
        self.status = try container.decode(String.self, forKey: .status)
        
        // Requires or Allow
        if self.status == AssessmentStatusType.requires {
            // Check what type of assessment factor we need to decode.
            if container.contains(.allowedFactors) {
                self.factors = try container.decode([AllowedFactor].self, forKey: .allowedFactors)
            }
            
            if container.contains(.enrolledFactors) {
                self.factors = try container.decode([EnrolledFactor].self, forKey: .enrolledFactors)
            }
            
            self.transactionId = try container.decodeIfPresent(String.self, forKey: .transactionId)
        }
        else if self.status == AssessmentStatusType.allow {
            self.token = nil
            
            // The token will end up being decoded as a dictionary.
            guard let result = try container.decodeIfPresent(Dictionary<String, Any>.self, forKey: .token) else {
                return
            }
            
            
            // Convert the dictionary of [String: Any] back to a JSON string.
            if let data = try? JSONSerialization.data(withJSONObject: result,
                options: []) {
                self.token = String(data: data, encoding: .utf8)
            }
        }
    }
}

public struct AnyDecodable: Decodable {
    public var value: Any

    private struct CodingKeys: CodingKey {
        var stringValue: String
        var intValue: Int?
    
        init?(intValue: Int) {
            self.stringValue = "\(intValue)"
            self.intValue = intValue
        }
    
        init?(stringValue: String) {
            self.stringValue = stringValue
        }
    }

    public init(from decoder: Decoder) throws {
        if let container = try? decoder.container(keyedBy: CodingKeys.self) {
            var result = [String: Any]()
            try container.allKeys.forEach { key throws in
                result[key.stringValue] = try container.decode(AnyDecodable.self, forKey: key).value
            }
            value = result
        }
        else if var container = try? decoder.unkeyedContainer() {
            var result = [Any]()
            while !container.isAtEnd {
                result.append(try container.decode(AnyDecodable.self).value)
            }
            value = result
        }
        else if let container = try? decoder.singleValueContainer() {
            if let intVal = try? container.decode(Int.self) {
                value = intVal
            }
            else if let doubleVal = try? container.decode(Double.self) {
                value = doubleVal
            }
            else if let boolVal = try? container.decode(Bool.self) {
                value = boolVal
            }
            else if let stringVal = try? container.decode(String.self) {
                value = stringVal
            }
            else {
                throw DecodingError.dataCorruptedError(in: container, debugDescription: "the container contains nothing serialisable")
            }
        }
        else {
            throw DecodingError.dataCorrupted(DecodingError.Context(codingPath: decoder.codingPath, debugDescription: "Could not serialise"))
        }
    }
}
