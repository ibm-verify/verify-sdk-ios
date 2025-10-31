//
// Copyright contributors to the IBM Verify Adaptive SDK for iOS project
//

import Foundation

/// The adaptive error object.
public struct AdaptiveError: Error {
    /// Initializes a new instance of `AdaptiveError`.
    public init(with message: String) {
        self.message = message
    }
    
    /// The description of the error.
    public var message: String

    enum CodingKeys: String, CodingKey {
       case error
   }
}

extension AdaptiveError: Decodable {
    /// Creates a new instance by decoding from the given decoder.
    /// - Parameter decoder: The decoder to read data from.
    /// - Remark: This initializer throws an error if reading from the decoder fails, or if the data read is corrupted or otherwise invalid.
    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)

        self.message = try values.decode(String.self, forKey: .error)
    }
}
