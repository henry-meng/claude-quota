import Foundation
import Security

/// The OAuth credential Claude Code stores after you sign in.
struct ClaudeCredentials {
    var accessToken: String
    var expiresAt: Date?
    var subscriptionType: String?
    var rateLimitTier: String?

    /// Treat a token as unusable slightly before its stated expiry so we don't
    /// fire a request that is guaranteed to 401 mid-flight.
    var isExpired: Bool {
        guard let expiresAt else { return false }
        return expiresAt.timeIntervalSinceNow < 30
    }

    var planLabel: String? {
        Self.planLabel(subscriptionType: subscriptionType, rateLimitTier: rateLimitTier)
    }

    /// The plan badge Claude's own usage screen shows, rebuilt from what the
    /// credential happens to carry: `default_claude_max_5x` -> "Max (5x)".
    /// Falls back to `subscriptionType` when the tier is missing or unfamiliar.
    static func planLabel(subscriptionType: String?, rateLimitTier: String?) -> String? {
        if let tier = rateLimitTier?.lowercased(), !tier.isEmpty {
            var parts = tier
                .replacingOccurrences(of: "default_", with: "")
                .replacingOccurrences(of: "claude_", with: "")
                .split(separator: "_")
                .map(String.init)

            // A trailing "5x" is the plan multiplier, not part of its name.
            var multiplier: String?
            if let last = parts.last, last.hasSuffix("x"), Int(last.dropLast()) != nil {
                multiplier = last
                parts.removeLast()
            }

            let name = parts.map(\.capitalized).joined(separator: " ")
            if !name.isEmpty {
                return multiplier.map { "\(name) (\($0))" } ?? name
            }
        }

        guard let subscriptionType, !subscriptionType.isEmpty else { return nil }
        return subscriptionType.capitalized
    }
}

/// Lock-guarded box for the loaded credential. `load()` is called from the
/// refresh task, not the main actor, so the storage has to be safe on its own.
private final class CredentialCache: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: ClaudeCredentials?

    var value: ClaudeCredentials? {
        get { lock.withLock { stored } }
        set { lock.withLock { stored = newValue } }
    }
}

/// Reads Claude Code's stored login.
///
/// This is strictly read-only. We never write, refresh, or rotate the
/// credential: refreshing would rotate the refresh token out from under Claude
/// Code and could sign you out of it. When the token is expired we surface that
/// and wait for Claude Code to renew it on its own.
///
/// We also deliberately never set `CLAUDE_CODE_OAUTH_TOKEN` in any child
/// process — Claude Code deletes its Keychain entry on exit when that variable
/// is present.
enum ClaudeCredentialStore {
    /// The Keychain service name Claude Code writes under on macOS.
    private static let keychainService = "Claude Code-credentials"

    /// Cached so a poll doesn't touch the Keychain.
    ///
    /// Reading a Keychain item is access-controlled per signature. Doing it on
    /// every refresh means macOS can put an authorisation prompt on screen
    /// once a minute, which is unusable. Read once, hold it until the token
    /// expires or a request comes back 401, then read again.
    private static let cache = CredentialCache()

    static func load() -> ClaudeCredentials? {
        let previous = cache.value

        if let cached = previous, !cached.isExpired {
            Log.credentials.notice("load: using cached credential (fp \(Log.fingerprint(cached.accessToken), privacy: .public), expires in \(Log.secondsUntil(cached.expiresAt), privacy: .public)s)")
            return cached
        }

        if let stale = previous {
            Log.credentials.notice("load: cached credential expired (fp \(Log.fingerprint(stale.accessToken), privacy: .public), expired \(Log.secondsUntil(stale.expiresAt), privacy: .public)s) — re-reading Keychain")
        }

        let candidates = keychainCandidates()
        Log.credentials.notice("load: Keychain returned \(candidates.count, privacy: .public) blob(s)")

        for data in candidates {
            if let credentials = parse(data) {
                let fp = Log.fingerprint(credentials.accessToken)
                // The decisive datum: if this matches the expired one we just
                // dropped, Claude Code has not renewed and waiting is correct.
                // If it differs and we are still reporting expired, the bug is
                // ours.
                let changed = previous.map { Log.fingerprint($0.accessToken) != fp } ?? true
                Log.credentials.notice("load: parsed credential from Keychain (fp \(fp, privacy: .public), expires in \(Log.secondsUntil(credentials.expiresAt), privacy: .public)s, expired=\(credentials.isExpired, privacy: .public), changedFromCached=\(changed, privacy: .public))")
                cache.value = credentials
                return credentials
            }
        }

        Log.credentials.error("load: no parseable credential in \(candidates.count, privacy: .public) blob(s)")
        cache.value = nil
        return nil
    }

    /// Drop the cached credential so the next `load()` goes back to the
    /// Keychain. Called when the server rejects the token we hold.
    static func invalidate() {
        if let held = cache.value {
            Log.credentials.notice("invalidate: dropping credential fp \(Log.fingerprint(held.accessToken), privacy: .public) after server rejection")
        }
        cache.value = nil
    }

    /// Every Keychain blob under our service, the current user's first.
    ///
    /// Claude Code keys the item by macOS username. Taking a single match and
    /// whatever came back first meant a second item (another account, or a
    /// leftover login) could silently hand us someone else's quota.
    ///
    /// This takes two queries, not one. `kSecMatchLimitAll` together with
    /// `kSecReturnData` is rejected outright with `errSecParam`: the Keychain
    /// returns attributes for many items, or data for one, never data for
    /// many. So list the accounts first, then fetch each blob on its own.
    private static func keychainCandidates() -> [Data] {
        var accounts = accountNames()

        let currentUser = NSUserName()
        if let index = accounts.firstIndex(of: currentUser) {
            accounts.remove(at: index)
            accounts.insert(currentUser, at: 0)
        }

        let candidates = accounts.compactMap { blob(forAccount: $0) }
        if !candidates.isEmpty { return candidates }

        // No account attribute to match on, or none of them resolved. Fall
        // back to "whatever is under this service".
        return [blob(forAccount: nil)].compactMap { $0 }
    }

    /// Attributes only. Legal with `kSecMatchLimitAll`.
    static func accountsQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
    }

    /// Data for exactly one item. Legal only with `kSecMatchLimitOne`.
    static func blobQuery(account: String?) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        if let account { query[kSecAttrAccount as String] = account }
        return query
    }

    private static func accountNames() -> [String] {
        var result: CFTypeRef?
        guard SecItemCopyMatching(accountsQuery() as CFDictionary, &result) == errSecSuccess,
              let items = result as? [[String: Any]] else {
            return []
        }
        return items.compactMap { $0[kSecAttrAccount as String] as? String }
    }

    private static func blob(forAccount account: String?) -> Data? {
        var result: CFTypeRef?
        guard SecItemCopyMatching(blobQuery(account: account) as CFDictionary, &result) == errSecSuccess
        else { return nil }
        return result as? Data
    }

    /// The stored blob is `{"claudeAiOauth": {"accessToken": ..., "expiresAt": <ms>}}`.
    /// Older builds stored the inner object directly, so accept both shapes.
    private static func parse(_ data: Data) -> ClaudeCredentials? {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        let payload = (root["claudeAiOauth"] as? [String: Any]) ?? root
        guard let token = payload["accessToken"] as? String, !token.isEmpty else { return nil }

        var expiresAt: Date?
        if let milliseconds = payload["expiresAt"] as? Double {
            expiresAt = Date(timeIntervalSince1970: milliseconds / 1000)
        }

        return ClaudeCredentials(
            accessToken: token,
            expiresAt: expiresAt,
            subscriptionType: payload["subscriptionType"] as? String,
            rateLimitTier: payload["rateLimitTier"] as? String
        )
    }
}
