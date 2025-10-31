//
// Copyright contributors to the IBM Verify Adaptive Sample App for iOS project
//

import Foundation
import Adaptive

struct AdaptiveServiceResult: Decodable {
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
            guard let result = try container.decodeIfPresent(AnyDecodable.self, forKey: .token)?.value as? [String: Any] else {
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
