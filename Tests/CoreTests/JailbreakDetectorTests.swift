//
// Copyright contributors to the IBM Verify Core SDK for iOS project
//

import XCTest
@testable import Core

class JailbreakDetectorTests: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    // MARK: - Environment

    /// Tests that `check()` reports the simulator environment when running in
    /// the iOS Simulator.
    func testCheckReturnsSimulatorEnvironment() throws {
        // Given, When
        let result = JailbreakDetector.check()

        // Then
        #if targetEnvironment(simulator)
        XCTAssertEqual(result.environment, .simulator)
        #else
        XCTAssertEqual(result.environment, .device)
        #endif
    }

    /// Tests that `wasEvaluated` is `false` on the Simulator because
    /// device-specific checks are not meaningful there.
    func testWasEvaluatedIsFalseOnSimulator() throws {
        // Given, When
        let result = JailbreakDetector.check()

        // Then
        #if targetEnvironment(simulator)
        XCTAssertFalse(result.wasEvaluated)
        #else
        XCTAssertTrue(result.wasEvaluated)
        #endif
    }

    // MARK: - Simulator signal suppression

    /// Tests that `unexpectedImageCount` is zero on the Simulator because the
    /// check is skipped and the result is hard-coded to a clean baseline.
    func testSimulatorSuppressesUnexpectedImageCount() throws {
        #if targetEnvironment(simulator)
        // Given, When
        let result = JailbreakDetector.check()

        // Then
        XCTAssertEqual(result.unexpectedImageCount, 0,
                       "unexpectedImageCount should be 0 on the Simulator")
        #else
        throw XCTSkip("Simulator-only test")
        #endif
    }

    /// Tests that `hasCompromiseIndicators` is `false` on the Simulator.
    func testHasCompromiseIndicatorsIsFalseOnSimulator() throws {
        #if targetEnvironment(simulator)
        // Given, When
        let result = JailbreakDetector.check()

        // Then
        XCTAssertFalse(result.hasCompromiseIndicators)
        #else
        throw XCTSkip("Simulator-only test")
        #endif
    }

    // MARK: - Triggered signals

    /// Tests that `triggeredSignals` always contains the environment identifier
    /// as its first element.
    func testTriggeredSignalsAlwaysContainsEnvironment() throws {
        // Given, When
        let result = JailbreakDetector.check()

        // Then
        XCTAssertTrue(result.triggeredSignals.first?.hasPrefix("environment:") == true,
                      "First triggered signal must be the environment identifier")
    }

    /// Tests that on the Simulator `triggeredSignals` contains only the
    /// environment identifier and no compromise signals.
    func testTriggeredSignalsOnSimulatorContainsOnlyEnvironment() throws {
        #if targetEnvironment(simulator)
        // Given, When
        let result = JailbreakDetector.check()

        // Then
        XCTAssertEqual(result.triggeredSignals, ["environment:simulator"],
                       "Simulator result should contain only the environment signal")
        #else
        throw XCTSkip("Simulator-only test")
        #endif
    }

    /// Tests that the `environment` raw value round-trips correctly for both
    /// known cases.
    func testEnvironmentRawValues() throws {
        // Given, When, Then
        XCTAssertEqual(JailbreakDetector.Environment.device.rawValue, "device")
        XCTAssertEqual(JailbreakDetector.Environment.simulator.rawValue, "simulator")
    }

    // MARK: - Unexpected image count

    /// Tests that a non-zero `unexpectedImageCount` is reflected in
    /// `triggeredSignals` with the expected prefix and embedded count.
    func testUnexpectedImageCountAppearsInTriggeredSignals() throws {
        // Given — construct a result with a non-zero image count directly so
        // the test is not tied to the runtime environment of the test host.
        let result = JailbreakDetector.Result(
            environment: .device,
            unexpectedImageCount: 3
        )

        // When
        let signals = result.triggeredSignals

        // Then
        XCTAssertTrue(
            signals.contains("unexpected_images:3"),
            "triggeredSignals must contain 'unexpected_images:3', got: \(signals)"
        )
    }

    /// Tests that a non-zero `unexpectedImageCount` sets `hasCompromiseIndicators`.
    func testUnexpectedImageCountNonZeroSetsCompromiseIndicator() throws {
        // Given
        let result = JailbreakDetector.Result(
            environment: .device,
            unexpectedImageCount: 1
        )

        // Then
        XCTAssertTrue(result.hasCompromiseIndicators,
                      "A non-zero unexpectedImageCount must set hasCompromiseIndicators")
    }

    /// Tests that a zero `unexpectedImageCount` does not set `hasCompromiseIndicators`.
    func testUnexpectedImageCountZeroDoesNotSetCompromiseIndicator() throws {
        // Given
        let result = JailbreakDetector.Result(
            environment: .device,
            unexpectedImageCount: 0
        )

        // Then
        XCTAssertFalse(result.hasCompromiseIndicators,
                       "A zero unexpectedImageCount must not set hasCompromiseIndicators")
    }

    /// Tests that a zero `unexpectedImageCount` is absent from `triggeredSignals`.
    func testUnexpectedImageCountZeroAbsentFromTriggeredSignals() throws {
        // Given
        let result = JailbreakDetector.Result(
            environment: .device,
            unexpectedImageCount: 0
        )

        // Then
        XCTAssertFalse(
            result.triggeredSignals.contains(where: { $0.hasPrefix("unexpected_images:") }),
            "triggeredSignals must not contain an unexpected_images entry when count is 0"
        )
    }

    /// Tests that `triggeredSignals` embeds the exact count value, not a
    /// placeholder, so callers can extract it for structured logging.
    func testTriggeredSignalsEmbedExactCount() throws {
        // Given
        let result = JailbreakDetector.Result(
            environment: .device,
            unexpectedImageCount: 7
        )

        // Then
        XCTAssertTrue(
            result.triggeredSignals.contains("unexpected_images:7"),
            "triggeredSignals must embed the exact anomaly count"
        )
    }
}
