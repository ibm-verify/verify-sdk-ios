//
// Copyright contributors to the IBM Verify Core SDK for iOS project
//

import Foundation

extension Data {
    /// Returns a Base-64 URL encoded string  as defined in [RFC4648](https://tools.ietf.org/html/rfc4648).
    /// - Parameter options: The options to use for the encoding. Default value is `[]`.
    /// - Returns: The Base-64 URL encoded string.
    public func base64UrlEncodedString(options: Data.Base64EncodingOptions = []) -> String {
        let result = base64EncodedString(options: options)
        let allowedCharacters = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._* +/=")
        
        guard var value = result.addingPercentEncoding(withAllowedCharacters: allowedCharacters) else {
            return ""
        }
        
        if options.contains(Data.Base64EncodingOptions.safeUrlCharacters) {
            value = value.replacingOccurrences(of: " ", with: "%20")
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
        }
        
        if options.contains(Data.Base64EncodingOptions.noPaddingCharacters) {
            value = value.replacingOccurrences(of: "=", with: "")
        }
        
        return value
    }
}

extension Data.Base64EncodingOptions {
    /// Encoder flag bit to indicate using the "URL and filename safe" variant of Base64 (see RFC 3548 section 4) where - and _ are used in place of + and /.
    public static let safeUrlCharacters = Data.Base64EncodingOptions(rawValue: UInt(1 << 9))
    
    /// Encoder flag bit to omit the padding '=' characters at the end of the output (if any).
    public static let noPaddingCharacters = Data.Base64EncodingOptions(rawValue: UInt(1 << 10))
}
