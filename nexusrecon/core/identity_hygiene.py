"""Identity input hygiene (Wave F-B5).

Junk/test identifiers (``abcfoo@``, ``test@``, ``noreply@``) leak into the
pipeline from probe targets and scraped pages, then poison everything
downstream: in the 2026-05-27 run ``abcfoo@ginandjuice.shop`` anchored a
"100% confidence flast naming convention" headline finding, got its own
phishing pretext bundle, and made it into the executive summary prose.

This module decides whether an email/handle is *obviously* synthetic so the
email-pattern analysis, pretext bundles, and findings can drop it. The bar is
deliberately high: a false positive silently discards a real target, so the
rules only fire on unmistakable placeholders, never on plausible names
(``barbara``, ``testa``, ``foster`` must all pass).
"""
from __future__ import annotations

#: Local parts that are never a real person, matched exactly.
_JUNK_EXACT: frozenset[str] = frozenset({
    "noreply", "no-reply", "donotreply", "do-not-reply", "postmaster",
    "mailer-daemon", "nobody", "none", "null", "na", "tbd", "xxx", "aaa",
    "user", "username", "email", "test", "example", "sample", "demo",
    "dummy", "fake", "placeholder", "foobar", "abcfoo", "asdf", "qwerty",
})

#: Placeholder tokens. A local part that decomposes *entirely* into these
#: (e.g. ``abcfoo`` = ``abc`` + ``foo``, ``foobar`` = ``foo`` + ``bar``) is
#: synthetic. Real names that merely *contain* a token (``bar`` in
#: ``barbara``) are NOT consumed end-to-end and so survive.
_JUNK_TOKENS: tuple[str, ...] = (
    "abc", "foo", "bar", "baz", "qux", "xyz", "asdf", "qwerty",
    "test", "demo", "lorem", "ipsum", "spam", "junk",
)


def _consumable_by_junk(local: str) -> bool:
    """True iff ``local`` splits cleanly into a sequence of junk tokens."""
    n = len(local)
    if n == 0:
        return False
    dp = [False] * (n + 1)
    dp[0] = True
    for i in range(1, n + 1):
        for tok in _JUNK_TOKENS:
            lt = len(tok)
            if i >= lt and dp[i - lt] and local[i - lt:i] == tok:
                dp[i] = True
                break
    return dp[n]


def is_probable_test_identity(identifier: str) -> bool:
    """Return True when ``identifier`` (an email or bare handle) is almost
    certainly a synthetic/test/role value, not a real person.

    Conservative by design: only fires on exact placeholder matches, local
    parts that fully decompose into junk tokens, or degenerate strings (a
    single repeated character). Anything else is treated as real.
    """
    if not identifier:
        return True
    ident = identifier.strip().lower()
    local = ident.split("@")[0] if "@" in ident else ident
    local = local.strip().strip(".")
    if not local:
        return True
    if local in _JUNK_EXACT:
        return True
    if len(set(local)) <= 1:  # "aaaa", "xxxx"
        return True
    if _consumable_by_junk(local):
        return True
    return False


def filter_test_identities(emails: list[str]) -> tuple[list[str], list[str]]:
    """Split ``emails`` into (real, dropped) by :func:`is_probable_test_identity`.

    Returns both so callers can record what was filtered (for the coverage /
    audit trail) rather than silently discarding input.
    """
    real: list[str] = []
    dropped: list[str] = []
    for e in emails:
        (dropped if is_probable_test_identity(e) else real).append(e)
    return real, dropped
