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

    /// Tests that all compromise signals are suppressed on the Simulator,
    /// where sandbox and filesystem restrictions differ from a real device.
    func testSimulatorSuppressesAllSignals() throws {
        #if targetEnvironment(simulator)
        // Given, When
        let result = JailbreakDetector.check()

        // Then
        XCTAssertFalse(result.suspiciousPaths,
                       "suspiciousPaths should be false on the Simulator")
        XCTAssertFalse(result.sandboxEscape,
                       "sandboxEscape should be false on the Simulator")
        XCTAssertFalse(result.suspiciousLibraries,
                       "suspiciousLibraries should be false on the Simulator")
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
}
