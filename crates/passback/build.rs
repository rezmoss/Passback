// Embeds build facts without timestamps or paths, so release builds stay reproducible.
fn main() {
    println!(
        "cargo:rustc-env=PASSBACK_TARGET={}",
        std::env::var("TARGET").unwrap_or_default()
    );
    println!(
        "cargo:rustc-env=PASSBACK_PROFILE={}",
        std::env::var("PROFILE").unwrap_or_default()
    );
    let commit = std::env::var("PASSBACK_GIT_COMMIT").unwrap_or_else(|_| "unknown".into());
    println!("cargo:rustc-env=PASSBACK_GIT_COMMIT={commit}");
    println!("cargo:rerun-if-env-changed=PASSBACK_GIT_COMMIT");
}
