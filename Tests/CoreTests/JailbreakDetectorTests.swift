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

    // MARK: - Helpers

    /// Constructs a clean (zero-count) device result.
    private func cleanDeviceResult() -> JailbreakDetector.Result {
        JailbreakDetector.Result(
            environment: .device,
            unexpectedImageCount: 0
        )
    }

    // MARK: - Environment

    /// Tests that `check()` reports the correct environment for the current
    /// build target.
    func testCheckReturnsCorrectEnvironment() throws {
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
    /// device-specific checks are intentionally skipped there.
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

    /// Tests that the `environment` raw values round-trip correctly.
    func testEnvironmentRawValues() throws {
        XCTAssertEqual(JailbreakDetector.Environment.device.rawValue, "device")
        XCTAssertEqual(JailbreakDetector.Environment.simulator.rawValue, "simulator")
    }

    // MARK: - Simulator signal suppression

    /// Tests that `unexpectedImageCount` is zero on the Simulator.
    func testSimulatorReturnsZeroUnexpectedImageCount() throws {
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

    /// Tests that `triggeredSignals` contains only the environment identifier
    /// on the Simulator.
    func testTriggeredSignalsOnSimulatorContainsOnlyEnvironment() throws {
        #if targetEnvironment(simulator)
        // Given, When
        let result = JailbreakDetector.check()

        // Then
        XCTAssertEqual(result.triggeredSignals, ["environment:simulator"])
        #else
        throw XCTSkip("Simulator-only test")
        #endif
    }

    // MARK: - triggeredSignals

    /// Tests that `triggeredSignals` always begins with the environment identifier.
    func testTriggeredSignalsAlwaysContainsEnvironment() throws {
        // Given, When
        let result = JailbreakDetector.check()

        // Then
        XCTAssertTrue(
            result.triggeredSignals.first?.hasPrefix("environment:") == true,
            "First triggered signal must be the environment identifier"
        )
    }

    /// Tests that a clean result produces only the environment identifier.
    func testCleanResultHasNoCompromiseSignals() throws {
        // Given
        let result = cleanDeviceResult()

        // Then
        XCTAssertEqual(result.triggeredSignals, ["environment:device"])
    }

    // MARK: - hasCompromiseIndicators

    /// Tests that a clean result does not set hasCompromiseIndicators.
    func testCleanResultHasNoCompromiseIndicators() throws {
        XCTAssertFalse(cleanDeviceResult().hasCompromiseIndicators)
    }

    /// Tests that a non-zero unexpectedImageCount sets hasCompromiseIndicators.
    func testNonZeroCountSetsCompromiseIndicator() throws {
        // Given
        let result = JailbreakDetector.Result(
            environment: .device,
            unexpectedImageCount: 1
        )

        // Then
        XCTAssertTrue(result.hasCompromiseIndicators)
    }

    // MARK: - triggeredSignals content

    /// Tests that a non-zero count produces an unexpected_images signal with
    /// the exact count embedded.
    func testUnexpectedImagesSignalContainsCount() throws {
        // Given
        let result = JailbreakDetector.Result(
            environment: .device,
            unexpectedImageCount: 3
        )

        // Then
        XCTAssertTrue(
            result.triggeredSignals.contains("unexpected_images:3"),
            "triggeredSignals must contain 'unexpected_images:3', got: \(result.triggeredSignals)"
        )
    }

    /// Tests that a zero count produces no unexpected_images signal.
    func testZeroCountAbsentFromTriggeredSignals() throws {
        // Given
        let result = cleanDeviceResult()

        // Then
        XCTAssertFalse(
            result.triggeredSignals.contains(where: { $0.hasPrefix("unexpected_images:") }),
            "triggeredSignals must not contain an unexpected_images entry when count is 0"
        )
    }

    /// Tests that the exact count value is embedded in triggeredSignals.
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
