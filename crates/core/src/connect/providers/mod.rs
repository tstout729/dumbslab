//! The apps people can connect. Each is one [`Connector`] in its own file; [`ALL`] lists them.

use super::Connector;

pub mod github;
pub mod gitlab;
pub mod google_drive;
pub mod linear;
pub mod shortcut;
pub mod todoist;

/// Every app this build can connect to, in the order Settings shows them.
pub static ALL: &[&dyn Connector] =
    &[&github::GitHub, &google_drive::GoogleDrive, &gitlab::GitLab, &linear::Linear, &shortcut::Shortcut, &todoist::Todoist];

pub fn get(id: &str) -> Option<&'static dyn Connector> {
    ALL.iter().copied().find(|c| c.info().id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_and_tidy() {
        let mut seen = std::collections::HashSet::new();
        for c in ALL {
            let info = c.info();
            assert!(seen.insert(info.id), "duplicate {}", info.id);
            assert!(info.id.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'), "{}", info.id);
            assert!(info.oauth.is_some() || info.token_fields.iter().any(|f| f.key == "token"), "{} can't be connected", info.id);
        }
    }
}
