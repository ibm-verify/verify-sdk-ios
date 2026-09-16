//
// Copyright contributors to the IBM Verify Core SDK for iOS project
//

import Foundation

/// Collects heuristic runtime indicators that the iOS execution environment
/// may have been modified or compromised.
///
/// Jailbreak detection is inherently heuristic. No individual check can
/// establish device integrity, and a sufficiently capable attacker may be
/// able to suppress or falsify the results.
///
/// Use `JailbreakDetector` as one input to the application's security policy.
/// It should not be treated as cryptographic proof that a device is or is not
/// jailbroken.
///
/// For server-authorized sensitive operations, complement these local signals
/// with server-side app-integrity controls such as App Attest.
public enum JailbreakDetector {

    // MARK: - Result

    /// Identifies the environment in which the checks were performed.
    public enum Environment: String, Sendable {
        /// Checks were performed on a physical iOS device.
        case device = "device"

        /// Checks were bypassed because the application is running in the
        /// iOS Simulator, where the device-specific checks are not meaningful.
        case simulator = "simulator"
    }

    /// The individual signals collected during a jailbreak/environment check.
    public struct Result: Sendable {

        // MARK: Properties

        /// Identifies whether the result was produced on a physical device or
        /// in the Simulator.
        public let environment: Environment

        /// Indicates that one or more known jailbreak-related filesystem
        /// artifacts were found.
        public let suspiciousPaths: Bool

        /// Indicates that the process was able to create a file outside its
        /// expected application sandbox.
        public let sandboxEscape: Bool

        /// Indicates that one or more known suspicious dynamic libraries were
        /// visible in the process's dyld image list.
        public let suspiciousLibraries: Bool

        // MARK: Derived State

        /// Indicates that at least one compromise indicator was observed.
        ///
        /// This property deliberately describes the evidence collected rather
        /// than asserting that the device is definitely jailbroken.
        public var hasCompromiseIndicators: Bool {
            suspiciousPaths
                || sandboxEscape
                || suspiciousLibraries
        }

        /// Returns stable identifiers for the signals that were triggered,
        /// including the environment in which the check was performed.
        ///
        /// The environment is always included as the first element so that
        /// the array is self-contained for structured logging or telemetry.
        /// A caller does not need to separately attach the environment to
        /// distinguish a clean simulator result from a clean device result.
        /// An array containing only the environment identifier indicates
        /// that no compromise signal was triggered.
        public var triggeredSignals: [String] {
            var signals: [String] = ["environment:\(environment.rawValue)"]

            if suspiciousPaths {
                signals.append("suspicious_paths")
            }

            if sandboxEscape {
                signals.append("sandbox_escape")
            }

            if suspiciousLibraries {
                signals.append("suspicious_libraries")
            }

            return signals
        }

        /// Indicates whether the checks were actually evaluated.
        ///
        /// Simulator results are explicitly marked as unevaluated rather than
        /// being represented as a falsely "clean" physical-device result.
        public var wasEvaluated: Bool {
            environment == .device
        }
    }

    // MARK: - Public API

    /// Performs the configured jailbreak/environment integrity checks.
    ///
    /// The checks are intentionally independent so callers can inspect the
    /// individual signals rather than relying on a single opaque Boolean.
    ///
    /// On the iOS Simulator, the device-specific checks are skipped because
    /// the Simulator does not provide the same filesystem and sandbox
    /// boundaries as a physical iOS device.
    ///
    /// - Returns: A `Result` containing the environment and all collected
    ///   compromise indicators.
    public static func check() -> Result {
        #if targetEnvironment(simulator)
        return Result(
            environment: .simulator,
            suspiciousPaths: false,
            sandboxEscape: false,
            suspiciousLibraries: false
        )
        #else
        return Result(
            environment: .device,
            suspiciousPaths: containsSuspiciousPaths(),
            sandboxEscape: canEscapeSandbox(),
            suspiciousLibraries: containsSuspiciousLibraries()
        )
        #endif
    }

    // MARK: - Device-only checks

    #if !targetEnvironment(simulator)

    // MARK: - Filesystem Checks

    /// Checks for filesystem artifacts commonly associated with jailbreak
    /// environments.
    ///
    /// The check uses the POSIX `access(2)` system call rather than relying on
    /// Foundation's higher-level file-existence APIs.
    ///
    /// A positive result means that at least one configured path was accessible
    /// at check time. A negative result does not establish that the device is
    /// unmodified because jailbreak artifacts can be removed, relocated, or
    /// otherwise hidden.
    private static func containsSuspiciousPaths() -> Bool {
        suspiciousPaths.contains { path in
            access(path, F_OK) == 0
        }
    }

    /// Filesystem locations commonly associated with jailbreak environments.
    ///
    /// This list is intentionally treated as a heuristic signature set rather
    /// than an authoritative list of jailbreak indicators.
    private static let suspiciousPaths: [String] = [
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",

        "/Library/MobileSubstrate",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/Library/PreferenceBundles",

        "/etc/apt",
        "/private/var/lib/apt",

        "/var/jb",
        "/var/jb/usr/bin/bash",
        "/var/jb/usr/lib/libhooker.dylib",
        "/var/jb/Library/MobileSubstrate",

        "/usr/sbin/sshd",
        "/bin/bash"
    ]

    // MARK: - Sandbox Check

    /// Attempts to create and remove a temporary file outside the application's
    /// normal sandbox.
    ///
    /// A successful write is a strong local indicator that expected sandbox
    /// restrictions are not being enforced for the process.
    ///
    /// Failure is the expected result on a normally sandboxed device and does
    /// not independently establish that the environment is trustworthy.
    ///
    /// - Note: On devices enrolled in MDM or enterprise profiles, the failed
    ///   write attempt may appear in file-access audit logs. This is benign
    ///   but worth accounting for in security-sensitive enterprise deployments.
    private static func canEscapeSandbox() -> Bool {
        let url = URL(
            filePath: "/private/jailbreak-test-\(UUID().uuidString)"
        )

        do {
            try Data("test".utf8).write(to: url, options: [.atomic])

            // Best-effort cleanup. The ability to create the file is the
            // security signal being tested.
            try? FileManager.default.removeItem(at: url)

            return true
        } catch {
            return false
        }
    }

    // MARK: - Dynamic Library Checks

    /// Checks the process's dyld image list for known suspicious libraries.
    ///
    /// This can identify libraries that are visible through dyld, including
    /// some jailbreak and instrumentation environments.
    ///
    /// The check is intentionally treated as partial coverage. Injection
    /// mechanisms that do not register their image with dyld may not appear in
    /// this list.
    private static func containsSuspiciousLibraries() -> Bool {
        let imageCount = _dyld_image_count()

        for index in 0..<imageCount {
            guard let imageNamePointer = _dyld_get_image_name(index) else {
                continue
            }

            let imageName = String(cString: imageNamePointer)

            if suspiciousLibraryNames.contains(where: {
                imageName.localizedCaseInsensitiveContains($0)
            }) {
                return true
            }
        }

        return false
    }

    /// Library names associated with known jailbreak or instrumentation
    /// environments.
    ///
    /// This list is a heuristic signature set and should be maintained as
    /// threat intelligence and supported jailbreak ecosystems change.
    private static let suspiciousLibraryNames: [String] = [
        "MobileSubstrate",
        "CydiaSubstrate",
        "SubstrateLoader",
        "TweakInject",
        "libhooker",
        "ElleKit",
        "FridaGadget"
    ]

    #endif
}
