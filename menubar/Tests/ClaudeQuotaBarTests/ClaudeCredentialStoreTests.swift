import XCTest
import Security
@testable import ClaudeQuotaBar

/// Exists because of a shipped bug: the account-disambiguation change asked
/// for `kSecReturnData` alongside `kSecMatchLimitAll`, the Keychain rejected
/// the query with `errSecParam`, and the app reported "Claude Code not logged
/// in" on a machine that was logged in fine. Nothing in the suite executed a
/// Keychain query, so nothing caught it.
///
/// These tests run the real queries. They assert on the *shape* being
/// acceptable, not on a credential existing, so they pass on a machine that
/// has never run Claude Code.
final class ClaudeCredentialStoreTests: XCTestCase {

    /// Statuses that mean "the query was well-formed". Anything about missing
    /// items or refused access is fine here; only malformed input is a bug.
    private let acceptable: Set<OSStatus> = [
        errSecSuccess,
        errSecItemNotFound,
        errSecInteractionNotAllowed,
        errSecAuthFailed,
        errSecUserCanceled
    ]

    private func run(_ query: [String: Any]) -> OSStatus {
        var result: CFTypeRef?
        return SecItemCopyMatching(query as CFDictionary, &result)
    }

    /// Point a query at a service nothing can match.
    ///
    /// The Keychain validates parameters before it looks anything up, so a
    /// query that can't match still returns `errSecParam` when it's malformed
    /// and `errSecItemNotFound` when it isn't. That's the whole assertion, and
    /// it skips the access-control evaluation that made the data fetch take
    /// 26 seconds against an unsigned test binary (and could put a Keychain
    /// prompt on someone's screen mid-test).
    private func unmatchable(_ query: [String: Any]) -> [String: Any] {
        var copy = query
        copy[kSecAttrService as String] = "claude-quota-tests.no-such-service"
        return copy
    }

    /// Attributes only, so this one is safe to run against the real service.
    func testAccountsQueryIsWellFormed() {
        let status = run(ClaudeCredentialStore.accountsQuery())
        XCTAssertNotEqual(status, errSecParam, "malformed accounts query")
        XCTAssertTrue(acceptable.contains(status), "unexpected status \(status)")
    }

    func testBlobQueriesAreWellFormed() {
        for account in [nil, NSUserName()] as [String?] {
            let status = run(unmatchable(ClaudeCredentialStore.blobQuery(account: account)))
            XCTAssertNotEqual(status, errSecParam, "malformed blob query for \(account ?? "any")")
            XCTAssertEqual(status, errSecItemNotFound, "unexpected status \(status)")
        }
    }

    /// The exact combination that broke it. Pinned so nobody folds the two
    /// queries back into one to save a round trip.
    func testDataCannotBeFetchedForAllMatchesAtOnce() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecReturnData as String: true,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        XCTAssertEqual(
            run(unmatchable(query)), errSecParam,
            "kSecReturnData with kSecMatchLimitAll is expected to be rejected"
        )
    }

    func testAccountsQueryAsksForAttributesNotData() {
        let query = ClaudeCredentialStore.accountsQuery()
        XCTAssertNil(query[kSecReturnData as String], "asking for data here is what failed")
        XCTAssertEqual(query[kSecReturnAttributes as String] as? Bool, true)
        XCTAssertEqual(query[kSecMatchLimit as String] as? String, kSecMatchLimitAll as String)
    }

    func testBlobQueryAsksForOneItem() {
        let query = ClaudeCredentialStore.blobQuery(account: "someone")
        XCTAssertEqual(query[kSecMatchLimit as String] as? String, kSecMatchLimitOne as String)
        XCTAssertEqual(query[kSecReturnData as String] as? Bool, true)
        XCTAssertEqual(query[kSecAttrAccount as String] as? String, "someone")
    }

    func testBlobQueryOmitsAccountWhenUnspecified() {
        XCTAssertNil(ClaudeCredentialStore.blobQuery(account: nil)[kSecAttrAccount as String])
    }
}
