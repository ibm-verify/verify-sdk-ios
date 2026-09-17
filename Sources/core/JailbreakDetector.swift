//
// Copyright contributors to the IBM Verify Core SDK for iOS project
//

import Foundation
import MachO

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
///
/// ## Detection approach
///
/// Rather than matching known jailbreak or instrumentation tool names — which
/// are trivially bypassed by renaming the injected dylib — the detector takes
/// a structural approach: it counts loaded dyld images whose paths fall outside
/// the application bundle and known system directories.
///
/// Any library injected by a jailbreak framework or instrumentation tool
/// (Frida, ElleKit, Cycript, etc.) must appear as an additional image at a
/// non-system path, regardless of what the file is named. Evasion requires
/// either re-signing the entire app bundle or making kernel-level filesystem
/// changes — both of which carry a much higher cost than a simple rename.
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

        /// The number of loaded dyld images whose paths do not belong to the
        /// application bundle or known system prefixes.
        ///
        /// A non-zero value suggests that unexpected libraries have been
        /// injected into the process. This count is informational; callers
        /// should interpret it alongside other signals and their own security
        /// policy.
        public let unexpectedImageCount: Int

        // MARK: Derived State

        /// Indicates that at least one compromise indicator was observed.
        ///
        /// This property deliberately describes the evidence collected rather
        /// than asserting that the device is definitely jailbroken.
        public var hasCompromiseIndicators: Bool {
            unexpectedImageCount > 0
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

            if unexpectedImageCount > 0 {
                signals.append("unexpected_images:\(unexpectedImageCount)")
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
    /// The check is intentionally structural: it counts loaded dyld images
    /// that fall outside the application bundle and known system directories
    /// rather than matching specific filenames or library identifiers. This
    /// approach is significantly harder to evade than name-based detection.
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
            unexpectedImageCount: 0
        )
        #else
        return Result(
            environment: .device,
            unexpectedImageCount: countUnexpectedImages()
        )
        #endif
    }

    // MARK: - Device-only checks

    #if !targetEnvironment(simulator)

    // MARK: - Unexpected Image Count

    /// Counts loaded dyld images whose paths do not originate from the
    /// application bundle or known system locations.
    ///
    /// Images injected by jailbreak frameworks or instrumentation tools
    /// (Frida, ElleKit, Cycript, and similar) typically reside outside the
    /// app bundle and outside standard system directories, so they appear as
    /// anomalies in this count regardless of what the file is named.
    ///
    /// Evasion requires either packaging the injected library inside the app
    /// bundle (which requires re-signing) or inside the system frameworks
    /// bundle (which requires kernel-level filesystem changes). Both carry a
    /// substantially higher cost than a simple dylib rename.
    ///
    /// - Returns: The number of images whose paths do not match any known
    ///   system or application prefix.
    private static func countUnexpectedImages() -> Int {
        let appBundle = Bundle.main.bundlePath
        let systemPrefixes = ["/System/", "/usr/lib/", "/Library/Caches/"]
        var anomalies = 0

        for i in 0..<_dyld_image_count() {
            guard let name = _dyld_get_image_name(i) else { continue }
            let path = String(cString: name)
            if path.hasPrefix(appBundle) { continue }
            if systemPrefixes.contains(where: path.hasPrefix) { continue }
            anomalies += 1
        }

        return anomalies
    }

    #endif
}
