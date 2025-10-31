//
// Copyright contributors to the IBM Verify Core SDK for iOS project
//
import Foundation

extension String {    
    /// A representation of the string suitable for url form encoding.
    ///
    /// The encoding supports Base-64 string values.   Does not include "?" or "/" with respect to [RFC 3986 Section 3.4](https://datatracker.ietf.org/doc/html/rfc3986#section-3.4).
    public var urlFormEncodedString: String {
        let generalDelimitersToEncode = ":#[]@" // does not include "?" or "/" due to RFC 3986 - Section 3.4
        let subDelimitersToEncode = "!$&'()*+,;="

        var allowedCharacterSet = CharacterSet.urlQueryAllowed
        allowedCharacterSet.remove(charactersIn: "\(generalDelimitersToEncode)\(subDelimitersToEncode)")

        return addingPercentEncoding(withAllowedCharacters: allowedCharacterSet) ?? self
    }
    
    /// Represents a Base-64 URL encoded string  as defined in [RFC4648](https://tools.ietf.org/html/rfc4648) with padding.
    public var base64UrlEncodedStringWithPadding: String {
        var value = replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        
        if value.count % 4 > 0 {
            value.append(String(repeating: "=", count: 4 - value.count % 4))
        }
        
        return value
    }
}
