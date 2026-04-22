//
//  Date+ExtensionTests.swift
//  IBM Verify
//
//  Created by Craig Pearson on 22/4/2026.
//

import XCTest
@testable import Core

final class DateFormatterExtensionsTests: XCTestCase {

    func testIso8061FormatterBehavior_Configuration() {
        let formatter = DateFormatter.iso8061FormatterBehavior
        
        // 1. Verify Format String
        XCTAssertEqual(formatter.dateFormat, "yyyy-MM-dd'T'HH:mm:ss.SSSZZZZZ")
        
        // 2. Verify Calendar
        XCTAssertEqual(formatter.calendar.identifier, .iso8601)
        
        // 3. Verify TimeZone (GMT/UTC)
        XCTAssertEqual(formatter.timeZone.secondsFromGMT(), 0)
        
        // 4. Verify Locale (en_US_POSIX is critical for fixed formats)
        XCTAssertEqual(formatter.locale.identifier, "en_US_POSIX")
    }
    
    func testIso8061FormatterBehavior_Encoding() {
        let formatter = DateFormatter.iso8061FormatterBehavior
        
        // Create a fixed date: 2026-04-22 15:00:00.123 UTC
        let components = DateComponents(
            calendar: formatter.calendar,
            timeZone: formatter.timeZone,
            year: 2026, month: 4, day: 22, hour: 15, minute: 0, second: 0, nanosecond: 123_000_000
        )
        guard let date = components.date else {
            XCTFail("Could not create date from components")
            return
        }
        
        let dateString = formatter.string(from: date)
        
        // ZZZZZ produces 'Z' for UTC/Zero offset
        XCTAssertEqual(dateString, "2026-04-22T15:00:00.123Z")
    }
    
    func testIso8061FormatterBehavior_Decoding() {
        let formatter = DateFormatter.iso8061FormatterBehavior
        let isoString = "2026-04-22T15:00:00.123Z"
        
        let date = formatter.date(from: isoString)
        
        XCTAssertNotNil(date)
        
        // Extract components back out to verify precision
        let components = formatter.calendar.dateComponents(in: formatter.timeZone, from: date!)
        XCTAssertEqual(components.year, 2026)
        XCTAssertEqual(components.month, 4)
        XCTAssertEqual(components.day, 22)
        XCTAssertEqual(components.hour, 15)
        XCTAssertEqual(components.nanosecond! / 1_000_000, 122) // Verify milliseconds
    }
    
    func testIso8061FormatterBehavior_InvalidInput() {
        let formatter = DateFormatter.iso8061FormatterBehavior
        let invalidString = "Not a date"
        
        let date = formatter.date(from: invalidString)
        
        XCTAssertNil(date)
    }
}
