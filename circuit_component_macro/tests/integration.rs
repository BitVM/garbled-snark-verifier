#[test]
fn success_cases() {
    let t = trybuild::TestCases::new();
    t.pass("tests/success/*.rs");
}

#[test]
fn fail_cases() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/fail/*.rs");
}
