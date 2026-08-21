#[test]
fn authorization_capabilities_are_not_constructable_deserializable_or_cloneable() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/verified_authorization_*.rs");
    tests.compile_fail("tests/ui/authorization_capability_*.rs");
}
