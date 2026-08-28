import Foundation
import os
import CryptoKit

/// Unified-logging channels for diagnosing refresh failures.
///
/// The app previously logged nothing, so a stuck "Login expired" left no
/// evidence: there was no way to tell whether the Keychain still held an
/// expired token or whether we were failing to pick up a renewed one.
///
/// Everything here is logged at `.notice` or `.error` so it persists and can be
/// read back after the fact. `.debug`/`.info` are memory-only by default and
/// would be gone by the time anyone looked.
///
/// Note on privacy: os.Logger redacts interpolated values unless they are
/// marked public. Diagnostic values are marked public deliberately; secrets
/// never reach the log at all (see `fingerprint`).
enum Log {
    private static let subsystem = "com.claudequota.ClaudeQuotaBar"

    static let refresh     = Logger(subsystem: subsystem, category: "refresh")
    static let credentials = Logger(subsystem: subsystem, category: "credentials")
    static let api         = Logger(subsystem: subsystem, category: "api")
    static let cache       = Logger(subsystem: subsystem, category: "cache")

    /// A short, stable identifier for a secret.
    ///
    /// This exists so the log can show that a token *changed* — the single most
    /// important fact when diagnosing "expired login that never recovers" —
    /// without the token itself ever being written anywhere.
    static func fingerprint(_ secret: String) -> String {
        SHA256.hash(data: Data(secret.utf8))
            .prefix(4)
            .map { String(format: "%02x", $0) }
            .joined()
    }

    /// Seconds until a date, as a whole number, for compact log lines.
    static func secondsUntil(_ date: Date?) -> String {
        guard let date else { return "never" }
        return String(Int(date.timeIntervalSinceNow.rounded()))
    }
}
