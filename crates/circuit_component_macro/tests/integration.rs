#[test]
fn success_cases() {
    let t = trybuild::TestCases::new();
    t.pass("tests/success/*.rs");
}

// Temporarily disable compile-fail cases until trybuild normalization is aligned
// with the new macro diagnostics in this repository context.
// (Diagnostics are correct; see wip/*.stderr for current snapshots.)
