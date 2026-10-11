import pytest

from sentinel import cvss, versions as V


@pytest.mark.parametrize("eco,a,b,expected", [
    ("npm", "1.10.0", "1.9.0", 1),            # not lexicographic
    ("npm", "1.0.0-alpha", "1.0.0", -1),      # prerelease < release
    ("npm", "1.0.0-alpha.1", "1.0.0-alpha.beta", -1),
    ("npm", "1.0.0-beta.11", "1.0.0-beta.2", 1),
    ("npm", "1.0.0+build.5", "1.0.0", 0),     # build metadata ignored
    ("Go", "v1.2.10", "v1.2.9", 1),
    ("PyPI", "2.0.0rc1", "2.0.0", -1),
    ("PyPI", "1.0.post1", "1.0", 1),
    ("PyPI", "1.10", "1.9", 1),
    ("Maven", "1.0-SNAPSHOT", "1.0", -1),
    ("Maven", "1.0-alpha", "1.0-beta", -1),
    ("Maven", "2.0", "2.0.0", 0),
    ("Maven", "2.17.1", "2.3", 1),
    ("NuGet", "1.0.0-preview", "1.0.0", -1),
    ("NuGet", "4.5.10.1", "4.5.9", 1),
])
def test_compare(eco, a, b, expected):
    assert V.compare(eco, a, b) == expected


def test_invalid_version_raises():
    with pytest.raises(V.VersionError):
        V.compare("npm", "not-a-version", "1.0.0")


@pytest.mark.parametrize("rng,ok,bad", [
    ("^1.2.3", ["1.2.3", "1.9.9"], ["2.0.0", "1.2.2", "2.0.0-0"]),
    ("^0.2.3", ["0.2.3", "0.2.9"], ["0.3.0"]),
    ("^0.0.3", ["0.0.3"], ["0.0.4"]),
    ("~1.2.3", ["1.2.9"], ["1.3.0"]),
    ("1.x", ["1.0.0", "1.99.0"], ["2.0.0"]),
    (">=1.0.0 <2.0.0 || >=3.0.0", ["1.5.0", "3.1.0"], ["2.5.0"]),
    ("1.2.3 - 2.3.4", ["1.2.3", "2.3.4"], ["2.3.5"]),
    ("*", ["0.0.1", "9.9.9"], []),
    ("4.17.1", ["4.17.1"], ["4.17.2"]),
    ("~6.16.0", ["6.16.3"], ["6.17.0"]),
])
def test_npm_ranges(rng, ok, bad):
    r = V.NpmRange(rng)
    for v in ok:
        assert r.satisfied_by(v), (rng, v)
    for v in bad:
        assert not r.satisfied_by(v), (rng, v)


def test_prerelease_excluded_from_plain_range():
    assert not V.NpmRange("^1.0.0").satisfied_by("1.5.0-beta.1")
    assert V.NpmRange(">=1.5.0-beta.0 <2").satisfied_by("1.5.0-beta.1")


def test_osv_range_semantics():
    aff = {"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}
    assert V.osv_affected("npm", "4.17.15", aff) is True
    assert V.osv_affected("npm", "4.17.21", aff) is False
    multi = {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": "1.5"}, {"introduced": "2.0"}, {"last_affected": "2.3"}]}]}
    assert V.osv_affected("PyPI", "1.4", multi) is True
    assert V.osv_affected("PyPI", "1.7", multi) is False
    assert V.osv_affected("PyPI", "2.3", multi) is True
    assert V.osv_affected("PyPI", "2.4", multi) is False
    explicit = {"versions": ["0.9.1"], "ranges": []}
    assert V.osv_affected("npm", "0.9.1", explicit) is True
    assert V.osv_affected("npm", "0.9.2", explicit) is False
    git_only = {"ranges": [{"type": "GIT", "events": [{"introduced": "abc"}]}]}
    assert V.osv_affected("npm", "1.0.0", git_only) is None  # unknown, not "safe"


def test_fixed_versions_and_major():
    aff = {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.4"}]}]}
    assert V.osv_fixed_versions("PyPI", "5.3.1", aff) == ["5.4"]
    assert V.is_major_change("npm", "0.21.1", "0.34.0") is True     # 0.x minor is breaking
    assert V.is_major_change("npm", "4.17.1", "4.22.3") is False
    assert V.is_major_change("npm", "1.2.3", "2.0.0") is True


def test_satisfies_ecosystems():
    assert V.satisfies("PyPI", "2.31.0", ">=2.0,<3") is True
    assert V.satisfies("PyPI", "1.9", ">=2.0") is False
    assert V.satisfies("Maven", "1.5", "[1.0,2.0)") is True
    assert V.satisfies("Maven", "2.0", "[1.0,2.0)") is False
    assert V.satisfies("npm", "1.0.0", "file:../x") is None


def test_cvss_v31_reference_vectors():
    # Values from the FIRST CVSS v3.1 calculator
    assert cvss.base_score_v3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cvss.base_score_v3("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H") == 7.2
    assert cvss.base_score_v3("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1
    assert cvss.base_score_v3("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N") == 0.0
    assert cvss.base_score_v3("CVSS:4.0/AV:N") is None
    assert cvss.base_score_v3("garbage") is None
