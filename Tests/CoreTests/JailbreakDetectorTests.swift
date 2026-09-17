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

    /// Constructs a clean (all-empty) device result.
    private func cleanDeviceResult() -> JailbreakDetector.Result {
        JailbreakDetector.Result(
            environment: .device,
            jailbreakPaths: [],
            knownLibraryPaths: [],
            unexpectedImagePaths: []
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

    /// Tests that all evidence arrays are empty on the Simulator.
    func testSimulatorReturnsEmptyEvidence() throws {
        #if targetEnvironment(simulator)
        // Given, When
        let result = JailbreakDetector.check()

        // Then
        XCTAssertTrue(result.jailbreakPaths.isEmpty,
                      "jailbreakPaths should be empty on the Simulator")
        XCTAssertTrue(result.knownLibraryPaths.isEmpty,
                      "knownLibraryPaths should be empty on the Simulator")
        XCTAssertTrue(result.unexpectedImagePaths.isEmpty,
                      "unexpectedImagePaths should be empty on the Simulator")
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

    /// Tests that a jailbreak path alone sets hasCompromiseIndicators.
    func testJailbreakPathSetsCompromiseIndicator() throws {
        // Given
        let result = JailbreakDetector.Result(
            environment: .device,
            jailbreakPaths: ["/var/jb/usr/lib/libhooker.dylib"],
            knownLibraryPaths: [],
            unexpectedImagePaths: []
        )

        // Then
        XCTAssertTrue(result.hasCompromiseIndicators)
    }

    /// Tests that a known library path alone sets hasCompromiseIndicators.
    func testKnownLibraryPathSetsCompromiseIndicator() throws {
        // Given
        let result = JailbreakDetector.Result(
            environment: .device,
            jailbreakPaths: [],
            knownLibraryPaths: ["/tmp/frida-agent.dylib"],
            unexpectedImagePaths: []
        )

        // Then
        XCTAssertTrue(result.hasCompromiseIndicators)
    }

    /// Tests that an unexpected image path alone sets hasCompromiseIndicators.
    func testUnexpectedImagePathSetsCompromiseIndicator() throws {
        // Given
        let result = JailbreakDetector.Result(
            environment: .device,
            jailbreakPaths: [],
            knownLibraryPaths: [],
            unexpectedImagePaths: ["/private/var/unknown.dylib"]
        )

        // Then
        XCTAssertTrue(result.hasCompromiseIndicators)
    }

    // MARK: - triggeredSignals content

    /// Tests that jailbreak paths emit a jailbreak_paths signal with the correct count.
    func testJailbreakPathsSignal() throws {
        // Given
        let result = JailbreakDetector.Result(
            environment: .device,
            jailbreakPaths: ["/var/jb/a.dylib", "/var/jb/b.dylib"],
            knownLibraryPaths: [],
            unexpectedImagePaths: []
        )

        // Then
        XCTAssertTrue(result.triggeredSignals.contains("jailbreak_paths:2"))
        XCTAssertFalse(result.triggeredSignals.contains(where: { $0.hasPrefix("known_libraries:") }))
        XCTAssertFalse(result.triggeredSignals.contains(where: { $0.hasPrefix("unexpected_images:") }))
    }

    /// Tests that known library paths emit a known_libraries signal with the correct count.
    func testKnownLibrariesSignal() throws {
        // Given
        let result = JailbreakDetector.Result(
            environment: .device,
            jailbreakPaths: [],
            knownLibraryPaths: ["/tmp/frida-agent.dylib"],
            unexpectedImagePaths: []
        )

        // Then
        XCTAssertTrue(result.triggeredSignals.contains("known_libraries:1"))
        XCTAssertFalse(result.triggeredSignals.contains(where: { $0.hasPrefix("jailbreak_paths:") }))
        XCTAssertFalse(result.triggeredSignals.contains(where: { $0.hasPrefix("unexpected_images:") }))
    }

    /// Tests that unexpected image paths emit an unexpected_images signal with the correct count.
    func testUnexpectedImagesSignal() throws {
        // Given
        let result = JailbreakDetector.Result(
            environment: .device,
            jailbreakPaths: [],
            knownLibraryPaths: [],
            unexpectedImagePaths: ["/private/var/a.dylib", "/private/var/b.dylib", "/private/var/c.dylib"]
        )

        // Then
        XCTAssertTrue(result.triggeredSignals.contains("unexpected_images:3"))
        XCTAssertFalse(result.triggeredSignals.contains(where: { $0.hasPrefix("jailbreak_paths:") }))
        XCTAssertFalse(result.triggeredSignals.contains(where: { $0.hasPrefix("known_libraries:") }))
    }

    /// Tests that all three signals appear together when all buckets are populated.
    func testAllThreeSignalsTriggerTogether() throws {
        // Given
        let result = JailbreakDetector.Result(
            environment: .device,
            jailbreakPaths: ["/var/jb/x.dylib"],
            knownLibraryPaths: ["/tmp/substrate.dylib"],
            unexpectedImagePaths: ["/private/var/unknown.dylib"]
        )

        // Then
        let signals = result.triggeredSignals
        XCTAssertTrue(signals.contains("jailbreak_paths:1"))
        XCTAssertTrue(signals.contains("known_libraries:1"))
        XCTAssertTrue(signals.contains("unexpected_images:1"))
    }

    /// Tests that absent signal buckets do not appear in triggeredSignals.
    func testEmptyBucketsAbsentFromTriggeredSignals() throws {
        // Given
        let result = cleanDeviceResult()

        // Then
        let signals = result.triggeredSignals
        XCTAssertFalse(signals.contains(where: { $0.hasPrefix("jailbreak_paths:") }))
        XCTAssertFalse(signals.contains(where: { $0.hasPrefix("known_libraries:") }))
        XCTAssertFalse(signals.contains(where: { $0.hasPrefix("unexpected_images:") }))
    }
}
