//! External entity resolution.

use bytes::Bytes;

use crate::error::{ParseError, ParseResult};

/// Application-supplied resolver for external DTD subsets and entities.
///
/// Returning `Ok(None)` means "use default resolution" (typically refuse
/// unless a filesystem fallback is configured by the caller). Returning
/// `Ok(Some(bytes))` supplies the entity content. Returning `Err` aborts.
pub trait EntityResolver {
    fn resolve(
        &mut self,
        public_id: Option<&str>,
        system_id: &str,
        base_uri: Option<&str>,
    ) -> ParseResult<Option<ResolvedEntity>>;

    /// EntityResolver2-style resolve with entity name (general, `%pe`, or `[dtd]`).
    fn resolve_entity(
        &mut self,
        _name: &str,
        public_id: Option<&str>,
        system_id: &str,
        base_uri: Option<&str>,
    ) -> ParseResult<Option<ResolvedEntity>> {
        self.resolve(public_id, system_id, base_uri)
    }
}

/// Bytes returned by an [`EntityResolver`], with optional system id override.
#[derive(Debug, Clone)]
pub struct ResolvedEntity {
    pub data: Bytes,
    pub public_id: Option<String>,
    pub system_id: Option<String>,
}

impl ResolvedEntity {
    pub fn new(data: impl Into<Bytes>) -> Self {
        Self {
            data: data.into(),
            public_id: None,
            system_id: None,
        }
    }
}

/// Default resolver that always refuses external resources (secure default).
#[derive(Debug, Default, Clone, Copy)]
pub struct RefusingEntityResolver;

impl EntityResolver for RefusingEntityResolver {
    fn resolve(
        &mut self,
        _public_id: Option<&str>,
        _system_id: &str,
        _base_uri: Option<&str>,
    ) -> ParseResult<Option<ResolvedEntity>> {
        Ok(None)
    }
}

/// Filesystem resolver for conformance tests and apps that opt in.
///
/// Respects `access_external_dtd` protocol allow-list (`""` = none, `"all"` =
/// any, otherwise comma-separated protocols).
#[derive(Debug, Clone)]
pub struct FileEntityResolver {
    pub access_external_dtd: String,
}

impl Default for FileEntityResolver {
    fn default() -> Self {
        Self {
            access_external_dtd: "file".to_string(),
        }
    }
}

impl FileEntityResolver {
    pub fn protocol_allowed(&self, system_id: &str) -> bool {
        let access = self.access_external_dtd.trim();
        if access.is_empty() {
            return false;
        }
        if access.eq_ignore_ascii_case("all") {
            return true;
        }
        let protocol = system_id
            .split_once(':')
            .map(|(p, _)| p)
            .unwrap_or("file");
        access
            .split(',')
            .map(str::trim)
            .any(|p| p.eq_ignore_ascii_case(protocol))
    }

    pub fn resolve_path(base_uri: Option<&str>, system_id: &str) -> ParseResult<std::path::PathBuf> {
        use std::path::{Path, PathBuf};

        if let Some(rest) = system_id.strip_prefix("file:") {
            let path = rest.trim_start_matches('/');
            // file:///abs or file:/abs
            let p = if rest.starts_with("///") || rest.starts_with("//") {
                PathBuf::from(if cfg!(windows) {
                    rest.trim_start_matches('/')
                } else if rest.starts_with("///") {
                    // Keep leading slash for absolute Unix paths: file:///foo -> /foo
                    &rest[2..]
                } else if let Some(s) = rest.strip_prefix("//localhost") {
                    s
                } else if rest.starts_with("//") {
                    // file://host/path — uncommon; treat path after host
                    if let Some(idx) = rest[2..].find('/') {
                        &rest[2 + idx..]
                    } else {
                        path
                    }
                } else {
                    path
                })
            } else if rest.starts_with('/') {
                PathBuf::from(rest)
            } else {
                PathBuf::from(path)
            };
            return Ok(p);
        }

        let path = Path::new(system_id);
        if path.is_absolute() {
            return Ok(path.to_path_buf());
        }

        // Scanner often pre-resolves relative IDs against the document base
        // (e.g. "../gonzalez/xmlconf/.../001.ent"). If that path already
        // exists, do not join against base again (which would double it).
        if path.exists() {
            return Ok(path.to_path_buf());
        }

        if let Some(base) = base_uri {
            let base_path = if let Some(rest) = base.strip_prefix("file:") {
                PathBuf::from(if rest.starts_with("///") {
                    &rest[2..]
                } else if rest.starts_with('/') {
                    rest
                } else {
                    rest.trim_start_matches('/')
                })
            } else {
                PathBuf::from(base)
            };
            let parent = base_path.parent().unwrap_or(Path::new("."));
            let joined = parent.join(system_id);
            return Ok(joined);
        }

        Ok(PathBuf::from(system_id))
    }
}

impl EntityResolver for FileEntityResolver {
    fn resolve(
        &mut self,
        public_id: Option<&str>,
        system_id: &str,
        base_uri: Option<&str>,
    ) -> ParseResult<Option<ResolvedEntity>> {
        let resolved_uri = resolve_uri(base_uri, system_id);
        // Relative paths and file: URIs need "file" (or "all") in the allow-list.
        let allowed = self.protocol_allowed(&resolved_uri)
            || self.protocol_allowed(system_id)
            || (!system_id.contains(':') && self.protocol_allowed("file"));
        if !allowed {
            return Ok(None);
        }

        // Try candidates: as-is (pre-resolved), then joined against base.
        let mut candidates = Vec::new();
        candidates.push(std::path::PathBuf::from(system_id));
        if let Ok(joined) = Self::resolve_path(base_uri, system_id) {
            if !candidates.iter().any(|c| c == &joined) {
                candidates.push(joined);
            }
        }
        let via_uri = std::path::PathBuf::from(&resolved_uri);
        if !candidates.iter().any(|c| c == &via_uri) {
            candidates.push(via_uri);
        }

        let mut last_err = None;
        for path in &candidates {
            match std::fs::read(path) {
                Ok(data) => {
                    let mut entity = ResolvedEntity::new(Bytes::from(data));
                    entity.public_id = public_id.map(str::to_string);
                    entity.system_id = Some(path.to_string_lossy().into_owned());
                    return Ok(Some(entity));
                }
                Err(e) => last_err = Some((path.clone(), e)),
            }
        }

        let (path, e) = last_err.unwrap();
        Err(ParseError::new(format!(
            "Failed to read external entity {}: {e}",
            path.display()
        )))
    }
}

/// RFC3986-ish relative resolve for system identifiers.
pub fn resolve_uri(base: Option<&str>, system_id: &str) -> String {
    if system_id.contains("://") || system_id.starts_with("file:") {
        return system_id.to_string();
    }
    if let Some(base) = base {
        if let Some((prefix, _)) = base.rsplit_once('/') {
            return format!("{prefix}/{system_id}");
        }
    }
    system_id.to_string()
}

/// External ID pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalId {
    pub public_id: Option<String>,
    pub system_id: Option<String>,
}
