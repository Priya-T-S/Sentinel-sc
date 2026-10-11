"""Manifest/lockfile parsing, graph reconstruction and negative cases."""
from helpers import names, parse_files


def _path_names(ctx, pid):
    return [[ctx.graph.packages[n].name if n in ctx.graph.packages else "ROOT" for n in p] for p in ctx.graph.paths_to(pid)]


def test_package_lock_v3_nested_resolution_and_scopes():
    lock = {"name": "app", "lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"a": "^1.0.0"}, "devDependencies": {"t": "1.0.0"}},
        "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "^2.0.0"}, "integrity": "sha512-AAA", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz"},
        "node_modules/b": {"version": "2.1.0", "integrity": "sha512-BBB", "resolved": "https://registry.npmjs.org/b/-/b-2.1.0.tgz"},
        "node_modules/a/node_modules/b": {"version": "2.0.5", "integrity": "sha512-CCC", "resolved": "https://registry.npmjs.org/b/-/b-2.0.5.tgz"},
        "node_modules/t": {"version": "1.0.0", "dev": True, "hasInstallScript": True, "resolved": "https://registry.npmjs.org/t/-/t-1.0.0.tgz"},
    }}
    pkg = {"name": "app", "dependencies": {"a": "^1.0.0"}, "devDependencies": {"t": "1.0.0"}}
    ctx, _ = parse_files({"package.json": pkg, "package-lock.json": lock})
    g = ctx.graph
    # a's dependency on b resolves to the NESTED copy (2.0.5), not the hoisted one
    assert "npm:b@2.0.5" in g.edges["npm:a@1.0.0"]
    assert "npm:b@2.1.0" not in g.edges["npm:a@1.0.0"]
    assert g.packages["npm:a@1.0.0"].direct and not g.packages["npm:b@2.0.5"].direct
    assert g.packages["npm:t@1.0.0"].scope == "dev" and g.packages["npm:t@1.0.0"].has_install_script
    assert _path_names(ctx, "npm:b@2.0.5") == [["ROOT", "a", "b"]]
    assert g.packages["npm:a@1.0.0"].integrity == "sha512-AAA"


def test_package_lock_v1_requires():
    lock = {"lockfileVersion": 1, "dependencies": {
        "x": {"version": "1.0.0", "requires": {"y": "^1.0.0"}, "dependencies": {"y": {"version": "1.2.0"}}},
        "y": {"version": "2.0.0"}}}
    ctx, _ = parse_files({"package.json": {"dependencies": {"x": "1.0.0", "y": "2.0.0"}}, "package-lock.json": lock})
    assert "npm:y@1.2.0" in ctx.graph.edges["npm:x@1.0.0"]


def test_lockfile_drift_detected():
    lock = {"lockfileVersion": 3, "packages": {"": {}, "node_modules/a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz", "integrity": "sha512-x"}}}
    ctx, _ = parse_files({"package.json": {"dependencies": {"a": "^2.0.0", "missing": "1.0.0"}}, "package-lock.json": lock})
    issues = {(d["name"], d["issue"].split()[0]) for d in ctx.drift}
    assert ("a", "locked") in issues and ("missing", "declared") in issues


def test_yarn_v1():
    yarn = '''# yarn lockfile v1

"lodash@^4.17.0", lodash@^4.17.15:
  version "4.17.15"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.15.tgz#abc"
  integrity sha512-XYZ

express@4.17.1:
  version "4.17.1"
  resolved "https://registry.yarnpkg.com/express/-/express-4.17.1.tgz"
  dependencies:
    lodash "^4.17.0"
'''
    ctx, _ = parse_files({"package.json": {"dependencies": {"express": "4.17.1"}}, "yarn.lock": yarn})
    assert ("lodash", "4.17.15") in names(ctx)
    assert "npm:lodash@4.17.15" in ctx.graph.edges["npm:express@4.17.1"]
    assert ctx.graph.packages["npm:express@4.17.1"].direct


def test_pnpm_v6_and_v9():
    v6 = '''lockfileVersion: '6.0'
importers:
  .:
    dependencies:
      express:
        specifier: 4.17.1
        version: 4.17.1
packages:
  /express@4.17.1:
    resolution: {integrity: sha512-AAA}
    dependencies:
      qs: 6.7.0
  /qs@6.7.0:
    resolution: {integrity: sha512-BBB}
'''
    ctx, _ = parse_files({"pnpm-lock.yaml": v6})
    assert "npm:qs@6.7.0" in ctx.graph.edges["npm:express@4.17.1"]
    v9 = '''lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      '@scope/pkg':
        specifier: ^1.0.0
        version: 1.0.0
packages:
  '@scope/pkg@1.0.0':
    resolution: {integrity: sha512-A}
  dep@2.0.0:
    resolution: {integrity: sha512-B}
snapshots:
  '@scope/pkg@1.0.0':
    dependencies:
      dep: 2.0.0
  dep@2.0.0: {}
'''
    ctx, _ = parse_files({"pnpm-lock.yaml": v9})
    assert "npm:dep@2.0.0" in ctx.graph.edges["npm:@scope/pkg@1.0.0"]
    assert ctx.graph.packages["npm:@scope/pkg@1.0.0"].direct


def test_requirements_pip_compile_edges_hashes_and_index():
    req = """--extra-index-url https://internal.example.com/simple
flask==3.0.0 \\
    --hash=sha256:aaa
    # via -r requirements.in
werkzeug==3.0.1
    # via flask
requests>=2
git+https://github.com/org/repo@main#egg=thing
"""
    ctx, _ = parse_files({"requirements.txt": req})
    g = ctx.graph
    assert "PyPI:werkzeug@3.0.1" in g.edges["PyPI:flask@3.0.0"]
    assert g.packages["PyPI:flask@3.0.0"].integrity == "sha256:aaa"
    assert not g.packages["PyPI:werkzeug@3.0.1"].direct
    assert g.packages["PyPI:requests@?"].version is None  # range: unresolved, never guessed
    assert any(r["kind"] == "pip-extra-index" for r in ctx.registries)
    assert any(u["name"] == "thing" and "SHA" in u["reason"] for u in ctx.unpinned)


def test_requirements_include_cannot_escape_repo():
    ctx, _ = parse_files({"app/requirements.txt": "-r ../../../etc/passwd\nsix==1.16.0\n"})
    assert ("six", "1.16.0") in names(ctx)


def test_poetry_lock_and_pyproject():
    pyproject = '[tool.poetry]\nname = "svc"\n[tool.poetry.dependencies]\npython = "^3.10"\nrequests = "^2.25"\n'
    lock = '''[[package]]
name = "requests"
version = "2.25.1"
[package.dependencies]
urllib3 = ">=1.21.1,<1.27"

[[package]]
name = "urllib3"
version = "1.26.4"
'''
    ctx, _ = parse_files({"pyproject.toml": pyproject, "poetry.lock": lock})
    assert "PyPI:urllib3@1.26.4" in ctx.graph.edges["PyPI:requests@2.25.1"]
    assert ctx.graph.packages["PyPI:requests@2.25.1"].direct


def test_pipfile_lock():
    lock = {"_meta": {"sources": [{"url": "https://pypi.org/simple"}]},
            "default": {"django": {"version": "==3.2.0", "hashes": ["sha256:x"]}}, "develop": {"pytest": {"version": "==7.0.0"}}}
    ctx, _ = parse_files({"Pipfile.lock": lock})
    assert ctx.graph.packages["PyPI:pytest@7.0.0"].scope == "dev"


def test_go_mod_sum():
    gomod = "module example.com/app\n\ngo 1.21\n\nrequire (\n\tgolang.org/x/text v0.3.7\n\tgithub.com/x/y v1.0.0 // indirect\n)\n"
    gosum = "golang.org/x/text v0.3.7 h1:abc=\ngolang.org/x/text v0.3.7/go.mod h1:def=\n"
    ctx, _ = parse_files({"go.mod": gomod, "go.sum": gosum})
    t = ctx.graph.packages["Go:golang.org/x/text@v0.3.7"]
    assert t.direct and t.integrity == "h1:abc="
    assert not ctx.graph.packages["Go:github.com/x/y@v1.0.0"].direct


def test_cargo_lock():
    lock = '''version = 3
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["serde", "time 0.1.43"]

[[package]]
name = "serde"
version = "1.0.100"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc"

[[package]]
name = "time"
version = "0.1.43"
source = "registry+https://github.com/rust-lang/crates.io-index"
'''
    ctx, _ = parse_files({"Cargo.lock": lock})
    root = next(iter(ctx.graph.roots))
    assert "crates.io:time@0.1.43" in ctx.graph.edges[root]


def test_pom_properties():
    pom = '''<project xmlns="http://maven.apache.org/POM/4.0.0"><groupId>g</groupId><artifactId>a</artifactId>
<properties><log4j.version>2.14.1</log4j.version></properties>
<dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId>
<version>${log4j.version}</version></dependency>
<dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>[4.0,5.0)</version><scope>test</scope></dependency>
</dependencies></project>'''
    ctx, _ = parse_files({"pom.xml": pom})
    p = ctx.graph.packages["Maven:org.apache.logging.log4j:log4j-core@2.14.1"]
    assert p.direct and p.version_exact
    assert ctx.graph.packages["Maven:junit:junit@?"].scope == "test"   # range: unresolved, flagged
    assert any(u["name"] == "junit:junit" for u in ctx.unpinned)


def test_nuget_lock():
    lock = {"version": 1, "dependencies": {"net8.0": {
        "Newtonsoft.Json": {"type": "Direct", "requested": "[12.0.1, )", "resolved": "12.0.1", "contentHash": "abc",
                            "dependencies": {"System.Memory": "4.5.0"}},
        "System.Memory": {"type": "Transitive", "resolved": "4.5.0"}}}}
    ctx, _ = parse_files({"packages.lock.json": lock})
    assert "NuGet:System.Memory@4.5.0" in ctx.graph.edges["NuGet:Newtonsoft.Json@12.0.1"]


def test_cyclonedx_import():
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"component": {"bom-ref": "app", "name": "app"}},
           "components": [{"bom-ref": "c1", "purl": "pkg:npm/lodash@4.17.15"},
                          {"bom-ref": "c2", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
                          {"bom-ref": "c3", "name": "no-purl"}],
           "dependencies": [{"ref": "app", "dependsOn": ["c1", "c2"]}]}
    ctx, _ = parse_files({"bom.json": bom})
    assert ("lodash", "4.17.15") in names(ctx, "npm")
    assert ("org.apache.logging.log4j:log4j-core", "2.14.1") in names(ctx, "Maven")
    out = ctx.outcomes[-1]
    assert out.status == "partial" and any("skipped" in l for l in out.limitations)


def test_malformed_inputs_reported_not_crashing():
    ctx, _ = parse_files({"package-lock.json": "{not json", "a/pom.xml": "<project><<", "b/poetry.lock": "[[[",
                          "c/pnpm-lock.yaml": "a: [unclosed", "d/package.json": "[1,2,3]"})
    statuses = {o.file: o.status for o in ctx.outcomes}
    assert statuses["package-lock.json"] == "error"
    assert statuses["a/pom.xml"] == "error"
    assert statuses["b/poetry.lock"] == "error"
    assert statuses["c/pnpm-lock.yaml"] == "error"
    assert statuses["d/package.json"] == "error"


def test_unsupported_files_are_reported_not_silently_clean():
    ctx, _ = parse_files({"setup.py": "import os; os.system('evil')", "Gemfile.lock": "GEM", "x.spdx.json": "{}"})
    st = {o.file: o.status for o in ctx.outcomes}
    assert st == {"setup.py": "unsupported", "Gemfile.lock": "unsupported", "x.spdx.json": "unsupported"}
    assert not ctx.graph.packages


def test_missing_lockfile_and_floating_versions():
    ctx, _ = parse_files({"package.json": {"dependencies": {"left": "latest", "pinned": "1.0.0", "range": "^2.0.0",
                                                            "git": "github:org/repo#main"}}})
    assert ctx.missing_lockfiles
    reasons = {u["name"]: u["reason"] for u in ctx.unpinned}
    assert "wildcard" in reasons["left"] and "lockfile" in reasons["range"] and "SHA" in reasons["git"]
    assert "pinned" not in reasons
    assert ctx.graph.packages["npm:pinned@1.0.0"].version == "1.0.0"
    assert ctx.graph.packages["npm:range@?"].version is None
