use developer_account_registry_interface::registry_admin;

#[test]
fn artifact_embeds_the_registry_admin() {
    let path = "../target/deploy/developer_account_registry.so";
    let bytes = std::fs::read(path).unwrap_or_else(|error| panic!("{path}: {error}"));
    let admin = registry_admin().to_bytes();
    assert!(
        bytes.windows(admin.len()).any(|window| window == admin),
        "{path} does not contain REGISTRY_ADMIN"
    );
}
