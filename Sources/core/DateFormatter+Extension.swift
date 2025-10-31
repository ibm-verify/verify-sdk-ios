//
// Copyright contributors to the IBM Verify Core SDK for iOS project
//

import Foundation

/// The [DateFormatter](https://developer.apple.com/documentation/foundation/dateformatter) extension class adds support for ISO8601 full date representations.
extension DateFormatter {
    /// Provides ISO 8601 formatting covering millisecond precision and timezone.
    ///
    /// ```swift
    /// let decoder = JSONDecoder()
    /// decoder.dateDecodingStrategy = .formatted(DateFormatter.iso8061FormatterBehavior)
    /// ```
    ///
    /// Supports `yyyy-MM-dd'T'HH:mm:ss.SSSZZZZZ` date strings.
    public static let iso8061FormatterBehavior: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZZZZZ"
        formatter.calendar = Calendar(identifier: .iso8601)
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.locale = Locale(identifier: "en_US_POSIX")
        return formatter
    }()
}
