//
// Copyright contributors to the IBM Verify Adaptive Sample App for iOS project
//


import Foundation
import Adaptive

struct AdaptiveGenerateResult: Decodable {
    var value: String
    
    /// The root level JSON structure for decoding.
    private enum CodingKeys: String, CodingKey {
        case correlation
    }

    /// Creates a new instance by decoding from the given decoder
    /// - parameter decoder: The decoder to read data from.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        // Value
        self.value = try container.decode(String.self, forKey: .correlation)
    }
}
