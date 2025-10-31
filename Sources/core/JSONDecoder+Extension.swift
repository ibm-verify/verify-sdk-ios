//
// Copyright contributors to the IBM Verify Core SDK for iOS project
//

import Foundation


extension JSONDecoder {
    /// Decodes a top-level value of the given type from the given JSON representation.
    /// - parameters:
    ///   - type: The type of the array to decode.
    ///   - data: The data to decode from.
    /// - returns: A value of the requested type.
    /// - throws: `DecodingError.typeMismatch` if values requested from the payload are corrupted, or if the given data is not valid JSON.
    /// - throws: An error if any value throws an error during decoding.
    ///
    /// ```swift
    /// struct Person: Codable {
    ///    public let id: Int
    ///    public let name: String
    /// }
    ///
    /// let json = """
    /// {
    ///    "count": 2,
    ///    "items": [{
    ///      "id": 1,
    ///      "name": "John Smith"
    ///    },
    ///    {
    ///      "id": 2,
    ///      "name": "Jane Doe"
    ///    }]
    /// }
    /// """
    ///
    /// let items = try JSONDecoder().decode(type: [Person].self, from: json.data(using: .utf8)!)
    ///  print(items)
    public func decode<T: Decodable>(type: [T].Type, from data: Data) throws -> [T] {
        guard let value = try decode(Element<T>.self, from: data).elements else {
            throw DecodingError.typeMismatch([String: Any].self, DecodingError.Context(codingPath: [], debugDescription: "Unable to decode JSON for type of [\(T.self)]."))
        }
        
        return value
    }
    
    /// Internal structure to decode an array of `Element`.
    private struct Element<T: Decodable>: Decodable {
        var elements: [T]? = nil
       
        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: UnknownCodingKeys.self)
            
            // Loop through each key in container.
            for key in container.allKeys {
                // Try tp decode array of T using key.
                if let elements = try? container.decode([T].self, forKey: UnknownCodingKeys(stringValue: key.stringValue)!) {
                    self.elements = elements
                    break
                }
            }
        }
    }
}
