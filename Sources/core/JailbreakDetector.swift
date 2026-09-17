//
// Copyright contributors to the IBM Verify Core SDK for iOS project
//

import Foundation
import MachO
#if DEBUG
import OSLog
#endif

/// Collects heuristic runtime indicators that the iOS execution environment
/// may have been modified or compromised.
///
/// Jailbreak detection is inherently heuristic. No individual runtime check
/// can establish device integrity, and a sufficiently capable attacker may
/// be able to suppress, alter, or bypass these checks.
///
/// `JailbreakDetector` should therefore be treated as one input to the
/// application's security policy rather than cryptographic proof that a
/// device is or is not jailbroken.
///
/// For server-authorized sensitive operations, combine local runtime signals
/// with server-side integrity controls such as App Attest.
///
/// ## Detection approach
///
/// This detector examines the Mach-O images currently loaded into the
/// application process through dyld.
///
/// It deliberately does not depend solely on matching the names of known
/// jailbreak or instrumentation libraries. A library can be renamed, while
/// an injected image still needs to be loaded into the process.
///
/// The detector therefore records loaded images whose paths are outside:
///
/// - the application bundle;
/// - standard iOS system image locations; and
/// - known Cryptex locations used by modern iOS releases.
///
/// Unexpected image locations are treated as **heuristic evidence only**.
/// A non-zero count does not, by itself, establish that the device is
/// jailbroken.
///
/// ## Platform
///
/// Device checks are compiled out for the iOS Simulator. Simulator execution
/// is reported explicitly through `Environment.simulator` rather than being
/// represented as a falsely "clean" physical-device result.
public enum JailbreakDetector {

    // MARK: - Result

    /// Identifies the environment in which the checks were performed.
    public enum Environment: String, Sendable {

        /// Checks were performed on a physical iOS device.
        case device = "device"

        /// Checks were skipped because the process is running in the
        /// iOS Simulator.
        case simulator = "simulator"
    }

    /// The result produced by `JailbreakDetector.check()`.
    public struct Result: Sendable {

        // MARK: Properties

        /// Identifies whether the result was produced on a physical device
        /// or in the Simulator.
        public let environment: Environment

        /// The number of loaded dyld images whose paths did not match the
        /// application bundle or a trusted system image prefix.
        ///
        /// A non-zero value indicates that the process loaded one or more
        /// images from locations that are not currently recognised by this
        /// detector.
        ///
        /// This is intentionally an evidence count, not a jailbreak score.
        public let unexpectedImageCount: Int

        // MARK: Derived State

        /// Indicates whether at least one heuristic compromise indicator
        /// was observed.
        ///
        /// `true` means evidence was observed; it does not mean the device
        /// has been proven to be jailbroken.
        public var hasCompromiseIndicators: Bool {
            unexpectedImageCount > 0
        }

        /// Returns stable identifiers for the signals observed by the check.
        ///
        /// The environment is always included as the first entry so the
        /// result remains self-describing when emitted to structured logs
        /// or telemetry.
        ///
        /// Example:
        ///
        ///     [
        ///         "environment:device",
        ///         "unexpected_images:2"
        ///     ]
        public var triggeredSignals: [String] {
            var signals: [String] = [
                "environment:\(environment.rawValue)"
            ]

            if unexpectedImageCount > 0 {
                signals.append(
                    "unexpected_images:\(unexpectedImageCount)"
                )
            }

            return signals
        }

        /// Indicates whether the physical-device checks were actually
        /// evaluated.
        ///
        /// Simulator results return `false` because the device-specific
        /// checks are intentionally skipped.
        public var wasEvaluated: Bool {
            environment == .device
        }
    }

    // MARK: - Logging

    #if DEBUG

    /// Diagnostic logger used during local testing.
    ///
    /// Production builds do not include the logger or diagnostic statements.
    private static let logger = Logger(
        subsystem: Bundle.main.bundleIdentifier
            ?? "JailbreakDetector",
        category: "JailbreakDetector"
    )

    #endif

    // MARK: - Public API

    /// Performs the configured jailbreak/environment integrity checks.
    ///
    /// The current implementation inspects the process's loaded Mach-O
    /// images and counts images whose paths do not belong to the application
    /// bundle or recognised system locations.
    ///
    /// On the iOS Simulator, the device-specific check is skipped and the
    /// returned environment is `.simulator`.
    ///
    /// - Returns: A `Result` containing the execution environment and the
    ///   heuristic indicators collected during the check.
    public static func check() -> Result {
        #if targetEnvironment(simulator)

        #if DEBUG
        logger.debug("Jailbreak checks skipped: running in Simulator")
        #endif

        return Result(
            environment: .simulator,
            unexpectedImageCount: 0
        )

        #else

        let unexpectedImageCount = countUnexpectedImages()

        #if DEBUG
        logger.debug(
            "Jailbreak image check completed. Unexpected images: \(unexpectedImageCount)"
        )
        #endif

        return Result(
            environment: .device,
            unexpectedImageCount: unexpectedImageCount
        )

        #endif
    }

    // MARK: - Device-only Checks

    #if !targetEnvironment(simulator)

    // MARK: - Trusted Image Prefixes

    /// Returns paths that are considered normal locations for Apple-provided
    /// system images on an iOS 18+ deployment target.
    ///
    /// This list is intentionally conservative and limited to broad system
    /// locations rather than individual dylib names.
    private static var trustedImagePrefixes: [String] {
        var prefixes = [
            // Core OS frameworks and libraries.
            "/System/",
            "/usr/lib/",

            // Modern iOS Cryptex content.
            //
            // iOS system components can be presented through Cryptex-backed
            // paths beneath this hierarchy.
            "/private/preboot/Cryptexes/"
        ]

        #if DEBUG

        // When a physical development device is attached to Xcode, developer
        // tooling may load from /Developer/. This exemption exists only in
        // DEBUG builds and therefore cannot suppress the same path in a
        // production build.
        prefixes.append("/Developer/")

        #endif

        return prefixes
    }

    // MARK: - Unexpected Image Detection

    /// Counts currently loaded dyld images that are not located in the
    /// application bundle or a recognised trusted system location.
    ///
    /// This is a heuristic runtime integrity signal.
    ///
    /// A legitimate image can be unexpected if Apple changes the system image
    /// layout in a future iOS release or if the application's runtime
    /// environment legitimately introduces another image location.
    ///
    /// Conversely, jailbreak and instrumentation frameworks can introduce
    /// additional images outside normal system locations.
    ///
    /// The result should therefore be interpreted together with other
    /// security signals rather than treated as an independent jailbreak
    /// verdict.
    ///
    /// - Returns: The number of loaded images classified as unexpected.
    private static func countUnexpectedImages() -> Int {
        let appBundle = Bundle.main.bundlePath

        // Require a path boundary after the bundle path.
        //
        // Without this, a path such as:
        //
        //     /private/.../MyApp.app.injected/foo.dylib
        //
        // would incorrectly match:
        //
        //     /private/.../MyApp.app
        //
        // Using a trailing slash avoids that prefix collision.
        let appBundlePrefix: String = {
            if appBundle.hasSuffix("/") {
                return appBundle
            }

            return appBundle + "/"
        }()

        let imageCount = _dyld_image_count()

        guard imageCount > 0 else {
            return 0
        }

        var anomalies = 0

        for index in 0..<imageCount {
            guard let imageName = _dyld_get_image_name(index) else {
                continue
            }

            let path = String(cString: imageName)

            // Ignore images belonging to the application bundle.
            if path.hasPrefix(appBundlePrefix) {
                continue
            }

            // Ignore recognised Apple/system image locations.
            if isTrustedSystemImagePath(path) {
                continue
            }

            anomalies += 1
        }

        return anomalies
    }

    // MARK: - Image Classification

    /// Determines whether a loaded image path belongs to a recognised
    /// system location.
    ///
    /// The prefixes end at directory boundaries so that unrelated paths such
    /// as `/usr/libfoo/` cannot accidentally be treated as `/usr/lib/`.
    ///
    /// - Parameter path: Absolute path returned by dyld.
    /// - Returns: `true` when the image is located beneath a trusted prefix.
    private static func isTrustedSystemImagePath(
        _ path: String
    ) -> Bool {
        trustedImagePrefixes.contains {
            path.hasPrefix($0)
        }
    }
    #endif
}