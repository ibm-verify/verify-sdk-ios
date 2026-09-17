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
/// application process through dyld. It collects three independent signals:
///
/// 1. **Jailbreak paths** — images loaded from known rootless jailbreak
///    locations (e.g. `/var/jb/`). These are unambiguously suspicious.
/// 2. **Known libraries** — images whose paths contain substrings associated
///    with known injection and instrumentation frameworks (Frida, Substrate,
///    ElleKit, etc.).
/// 3. **Unexpected images** — images whose paths are outside the application
///    bundle and all recognised system locations. These are a structural
///    signal: any injected library must be loaded from *somewhere*, and a
///    renamed tool still appears here.
///
/// Each signal is reported independently so callers can apply their own
/// policy threshold rather than relying on a single opaque boolean.
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

        /// Paths of images loaded from known rootless jailbreak locations
        /// (e.g. `/var/jb/`).
        ///
        /// Any entry here is an unambiguous signal: legitimate iOS system
        /// components are never staged under these paths.
        public let jailbreakPaths: [String]

        /// Paths of images whose filenames contain substrings associated
        /// with known injection or instrumentation frameworks.
        ///
        /// This catches default installs of tools such as Frida, Substrate,
        /// ElleKit, and Cycript that have not been renamed. It is
        /// complementary to `unexpectedImagePaths`, which catches renamed
        /// tools by location rather than by name.
        public let knownLibraryPaths: [String]

        /// Paths of images that are outside the application bundle and all
        /// recognised system locations, but did not match a known-bad prefix
        /// or library name.
        ///
        /// This is a structural signal: any injected library must be loaded
        /// from somewhere, so a renamed or novel tool still appears here.
        /// Callers should interpret this alongside `jailbreakPaths` and
        /// `knownLibraryPaths` rather than treating it as an independent
        /// verdict.
        public let unexpectedImagePaths: [String]

        // MARK: Derived State

        /// Indicates whether at least one heuristic compromise indicator
        /// was observed across all three signal categories.
        ///
        /// `true` means evidence was observed; it does not mean the device
        /// has been proven to be jailbroken.
        public var hasCompromiseIndicators: Bool {
            !jailbreakPaths.isEmpty
                || !knownLibraryPaths.isEmpty
                || !unexpectedImagePaths.isEmpty
        }

        /// Returns stable identifiers for the signals observed by the check.
        ///
        /// The environment is always included as the first entry so the
        /// result remains self-describing when emitted to structured logs
        /// or telemetry. An array containing only the environment identifier
        /// indicates that no compromise signal was triggered.
        ///
        /// Example output on a clean device:
        ///
        ///     ["environment:device"]
        ///
        /// Example output with evidence:
        ///
        ///     [
        ///         "environment:device",
        ///         "jailbreak_paths:1",
        ///         "known_libraries:1",
        ///         "unexpected_images:2"
        ///     ]
        public var triggeredSignals: [String] {
            var signals: [String] = [
                "environment:\(environment.rawValue)"
            ]

            if !jailbreakPaths.isEmpty {
                signals.append("jailbreak_paths:\(jailbreakPaths.count)")
            }

            if !knownLibraryPaths.isEmpty {
                signals.append("known_libraries:\(knownLibraryPaths.count)")
            }

            if !unexpectedImagePaths.isEmpty {
                signals.append("unexpected_images:\(unexpectedImagePaths.count)")
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
        subsystem: Bundle.main.bundleIdentifier ?? "JailbreakDetector",
        category: "JailbreakDetector"
    )

    #endif

    // MARK: - Public API

    /// Performs the configured jailbreak/environment integrity checks.
    ///
    /// The implementation inspects the process's loaded Mach-O images and
    /// classifies them into three independent evidence buckets:
    /// known jailbreak paths, known injection library names, and structurally
    /// unexpected image locations.
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
            jailbreakPaths: [],
            knownLibraryPaths: [],
            unexpectedImagePaths: []
        )

        #else

        let evidence = collectImageEvidence()

        #if DEBUG
        logger.debug(
            """
            Jailbreak image check completed. \
            Jailbreak paths: \(evidence.jailbreakPaths.count), \
            Known libraries: \(evidence.knownLibraryPaths.count), \
            Unexpected images: \(evidence.unexpectedImagePaths.count)
            """
        )
        #endif

        return Result(
            environment: .device,
            jailbreakPaths: evidence.jailbreakPaths,
            knownLibraryPaths: evidence.knownLibraryPaths,
            unexpectedImagePaths: evidence.unexpectedImagePaths
        )

        #endif
    }

    // MARK: - Device-only Checks

    #if !targetEnvironment(simulator)

    // MARK: - Evidence Collection

    private struct ImageEvidence {
        var jailbreakPaths: [String] = []
        var knownLibraryPaths: [String] = []
        var unexpectedImagePaths: [String] = []
    }

    /// Walks the dyld image list and classifies each loaded image into one
    /// of three evidence buckets.
    ///
    /// Classification order matters: a path is assigned to the first
    /// matching bucket and not evaluated further, so the higher-confidence
    /// signals (jailbreak paths, known library names) are checked before
    /// the catch-all structural bucket.
    private static func collectImageEvidence() -> ImageEvidence {
        let appBundlePrefix = appBundlePrefixWithSlash()
        let imageCount = _dyld_image_count()

        guard imageCount > 0 else {
            return ImageEvidence()
        }

        var evidence = ImageEvidence()

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

            // Bucket 1: known rootless jailbreak locations.
            if isJailbreakPath(path) {
                evidence.jailbreakPaths.append(path)
                continue
            }

            // Bucket 2: known injection/instrumentation library names.
            if isKnownLibrary(path) {
                evidence.knownLibraryPaths.append(path)
                continue
            }

            // Bucket 3: structural catch-all — unexpected location.
            evidence.unexpectedImagePaths.append(path)
        }

        return evidence
    }

    // MARK: - Trusted Image Prefixes

    /// Returns the application bundle path with a guaranteed trailing slash.
    ///
    /// Without the slash, a path such as `/private/.../MyApp.app.evil/foo.dylib`
    /// would incorrectly match the bundle prefix `/private/.../MyApp.app`.
    private static func appBundlePrefixWithSlash() -> String {
        let path = Bundle.main.bundlePath
        return path.hasSuffix("/") ? path : path + "/"
    }

    /// Returns paths considered normal locations for Apple-provided system
    /// images on an iOS 18+ deployment target.
    ///
    /// The list is conservative and limited to broad directory prefixes.
    /// All prefixes end with `/` to prevent partial-component collisions
    /// (e.g. `/usr/libfoo/` must not match the `/usr/lib/` prefix).
    private static var trustedImagePrefixes: [String] {
        var prefixes = [
            // Core OS frameworks and libraries.
            "/System/",
            "/usr/lib/",

            // Cryptex-backed system content (iOS 16+, always present on iOS 18).
            // The legacy /Library/Caches/ shared cache location is not used
            // on iOS 18 and is intentionally omitted.
            "/private/preboot/Cryptexes/",
        ]

        #if DEBUG
        // When a physical development device is attached to Xcode, developer
        // tooling may load images from /Developer/. This exemption exists
        // only in DEBUG builds and cannot suppress signals in production.
        prefixes.append("/Developer/")
        #endif

        return prefixes
    }

    /// Returns `true` when `path` is beneath a trusted system prefix.
    private static func isTrustedSystemImagePath(_ path: String) -> Bool {
        trustedImagePrefixes.contains { path.hasPrefix($0) }
    }

    // MARK: - Jailbreak Path Detection

    /// Path prefixes that are unambiguously associated with rootless
    /// jailbreak environments.
    ///
    /// Legitimate iOS system components are never staged under these paths.
    private static let jailbreakPrefixes: [String] = [
        "/var/jb/",
    ]

    /// Returns `true` when `path` originates from a known jailbreak location.
    private static func isJailbreakPath(_ path: String) -> Bool {
        jailbreakPrefixes.contains { path.hasPrefix($0) }
    }

    // MARK: - Known Library Detection

    /// Lowercase substrings present in the paths of known injection and
    /// instrumentation frameworks.
    ///
    /// This list catches default installs that have not been renamed.
    /// It is complementary to the structural bucket, which catches renamed
    /// tools by location.
    private static let knownLibrarySubstrings: [String] = [
        "substrate",
        "substitute",
        "frida",
        "cycript",
        "libhooker",
        "ellekit",
        "tweakinject",
    ]

    /// Returns `true` when the lowercase form of `path` contains a known
    /// injection or instrumentation library substring.
    private static func isKnownLibrary(_ path: String) -> Bool {
        let lower = path.lowercased()
        return knownLibrarySubstrings.contains { lower.contains($0) }
    }

    #endif
}
