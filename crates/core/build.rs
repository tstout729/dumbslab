use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    output.status.success().then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn main() {
    println!("cargo:rerun-if-env-changed=DUMBSLAB_GIT_SHA");
    println!("cargo:rerun-if-changed=build.rs");
    // Resolve Git's paths rather than assuming .git is a directory (worktrees use a file).
    for name in [Some("HEAD".to_owned()), git(&["symbolic-ref", "-q", "HEAD"]), Some("packed-refs".to_owned())].into_iter().flatten() {
        if let Some(path) = git(&["rev-parse", "--git-path", &name]) {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    let injected = std::env::var("DUMBSLAB_GIT_SHA").ok().filter(|s| !s.trim().is_empty());
    let sha = injected.or_else(|| git(&["rev-parse", "--verify", "HEAD"]));
    let sha = match sha {
        Some(sha) => {
            let sha = sha.trim();
            assert!(
                (sha.len() == 40 || sha.len() == 64) && sha.bytes().all(|b| b.is_ascii_hexdigit()),
                "DUMBSLAB_GIT_SHA must be a full hexadecimal Git commit SHA"
            );
            sha.to_ascii_lowercase()
        }
        None => "unknown".to_owned(),
    };
    println!("cargo:rustc-env=DUMBSLAB_BUILD_GIT_SHA={sha}");
}
