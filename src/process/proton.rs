//! Steam and Proton runtime identity reconciliation

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// One consistent Steam identity assembled from all available sources
pub(super) struct ProtonIdentity {
    pub(super) compatdata_dir: Option<PathBuf>,
    pub(super) app_id: Option<u32>,
    pub(super) proton_dist: Option<PathBuf>,
    pub(super) steam_client_path: Option<PathBuf>,
    pub(super) wine_prefix: Option<PathBuf>,
}

/// Resolves all Steam/Proton identity sources without precedence-based guesses
pub(super) fn resolve_proton_identity(
    environment: &BTreeMap<String, String>,
    command_compatdata_paths: &[PathBuf],
) -> Result<ProtonIdentity> {
    let (compatdata_dir, app_id) =
        resolve_steam_identity_sources(environment, command_compatdata_paths)?;
    let (wine_prefix, proton_dist, steam_client_path) =
        resolve_runtime_identity(environment, compatdata_dir.as_deref())?;

    Ok(ProtonIdentity {
        compatdata_dir,
        app_id,
        proton_dist,
        steam_client_path,
        wine_prefix,
    })
}

/// Reconciles compatdata paths and Steam application identifiers
fn resolve_steam_identity_sources(
    environment: &BTreeMap<String, String>,
    command_compatdata_paths: &[PathBuf],
) -> Result<(Option<PathBuf>, Option<u32>)> {
    let environment_path = environment.get("STEAM_COMPAT_DATA_PATH").map(PathBuf::from);
    if let Some(path) = environment_path.as_deref() {
        require_absolute_runtime_path("STEAM_COMPAT_DATA_PATH", path)?;
    }
    let mut path_candidates = Vec::new();
    if let Some(path) = environment_path {
        path_candidates.push(("STEAM_COMPAT_DATA_PATH".to_owned(), path));
    }
    path_candidates.extend(
        command_compatdata_paths
            .iter()
            .cloned()
            .map(|path| ("command line".to_owned(), path)),
    );

    let mut unique_paths: Vec<(String, PathBuf)> = Vec::new();
    for (source, path) in path_candidates {
        if unique_paths
            .iter()
            .any(|(_, existing)| equivalent_identity_path(existing, &path))
        {
            continue;
        }
        unique_paths.push((source, path));
    }
    if unique_paths.len() > 1 {
        return Err(Error::SteamIdentityConflict {
            details: format!(
                "compatdata paths disagree: {}",
                format_identity_paths(&unique_paths)
            ),
        });
    }

    let app_id_candidates = steam_app_id_candidates(environment, &unique_paths)?;
    let app_id = reconcile_app_ids(&app_id_candidates)?;
    let compatdata_dir = unique_paths.first().map(|(_, path)| path.clone());
    Ok((compatdata_dir, app_id))
}

/// Validates one prefix and all runtime paths used by Proton invocation
fn resolve_runtime_identity(
    environment: &BTreeMap<String, String>,
    compatdata_dir: Option<&Path>,
) -> Result<(Option<PathBuf>, Option<PathBuf>, Option<PathBuf>)> {
    let environment_prefix = environment.get("WINEPREFIX").map(PathBuf::from);
    if let Some(path) = environment_prefix.as_deref() {
        require_absolute_runtime_path("WINEPREFIX", path)?;
    }
    let compatdata_prefix = compatdata_dir.as_ref().map(|path| path.join("pfx"));
    let wine_prefix = match (environment_prefix, compatdata_prefix) {
        (Some(environment_prefix), Some(compatdata_prefix)) => {
            if !equivalent_identity_path(&environment_prefix, &compatdata_prefix) {
                return Err(Error::SteamIdentityConflict {
                    details: format!(
                        "WINEPREFIX={} does not match STEAM_COMPAT_DATA_PATH/pfx={}",
                        environment_prefix.display(),
                        compatdata_prefix.display()
                    ),
                });
            }
            Some(environment_prefix)
        }
        (Some(environment_prefix), None) => Some(environment_prefix),
        (None, Some(compatdata_prefix)) => Some(compatdata_prefix),
        (None, None) => None,
    }
    .map(|path| require_runtime_directory("Wine prefix", path))
    .transpose()?;

    let proton_dist = resolve_proton_dist(environment)?;
    let steam_client_path = environment
        .get("STEAM_COMPAT_CLIENT_INSTALL_PATH")
        .map(PathBuf::from);
    if let Some(path) = steam_client_path.as_deref() {
        require_absolute_runtime_path("STEAM_COMPAT_CLIENT_INSTALL_PATH", path)?;
    }

    Ok((wine_prefix, proton_dist, steam_client_path))
}

/// Resolves the explicit Proton path or the first documented tool path
fn resolve_proton_dist(environment: &BTreeMap<String, String>) -> Result<Option<PathBuf>> {
    if let Some(value) = environment.get("PROTONPATH") {
        let path = PathBuf::from(value);
        require_absolute_runtime_path("PROTONPATH", &path)?;
        return Ok(Some(path));
    }

    let mut first_tool_path = None;
    if let Some(value) = environment.get("STEAM_COMPAT_TOOL_PATHS") {
        for tool_path in value.split(':').filter(|path| !path.is_empty()) {
            let path = PathBuf::from(tool_path);
            require_absolute_runtime_path("STEAM_COMPAT_TOOL_PATHS", &path)?;
            if first_tool_path.is_none() {
                first_tool_path = Some(path);
            }
        }
    }
    Ok(first_tool_path)
}

/// Collects every AppID-bearing environment and path source
fn steam_app_id_candidates(
    environment: &BTreeMap<String, String>,
    paths: &[(String, PathBuf)],
) -> Result<Vec<(String, u32)>> {
    let mut candidates = Vec::new();
    for key in ["STEAM_COMPAT_APP_ID", "SteamAppId", "SteamGameId"] {
        if let Some(value) = environment.get(key) {
            let app_id = value
                .parse::<u32>()
                .map_err(|_| Error::SteamIdentityConflict {
                    details: format!("{key} is not a valid numeric AppID: {value:?}"),
                })?;
            candidates.push((key.to_owned(), app_id));
        }
    }
    for (source, path) in paths {
        let app_id =
            steam_app_id_from_compatdata_dir(path).ok_or_else(|| Error::SteamIdentityConflict {
                details: format!(
                    "{source} does not end in a numeric compatdata AppID: {}",
                    path.display()
                ),
            })?;
        candidates.push((format!("{source} path"), app_id));
    }
    Ok(candidates)
}

/// Requires every available `AppID` source to identify the same game
fn reconcile_app_ids(candidates: &[(String, u32)]) -> Result<Option<u32>> {
    let Some(first_app_id) = candidates.first().map(|(_, app_id)| *app_id) else {
        return Ok(None);
    };
    if candidates.iter().all(|(_, app_id)| *app_id == first_app_id) {
        return Ok(Some(first_app_id));
    }

    Err(Error::SteamIdentityConflict {
        details: format!(
            "AppID candidates disagree: {}",
            candidates
                .iter()
                .map(|(source, app_id)| format!("{source}={app_id}"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    })
}

/// Rejects runtime paths that cannot identify a Linux filesystem location
fn require_absolute_runtime_path(name: &str, path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(Error::SteamIdentityConflict {
            details: format!("{name} must be absolute: {}", path.display()),
        });
    }
    Ok(())
}

/// Requires an identity-bearing runtime path to exist and be a directory
fn require_runtime_directory(name: &str, path: PathBuf) -> Result<PathBuf> {
    let metadata = fs::metadata(&path).map_err(|source| Error::io(&path, source))?;
    if !metadata.is_dir() {
        return Err(Error::SteamIdentityConflict {
            details: format!("{name} is not a directory: {}", path.display()),
        });
    }
    Ok(path)
}

/// Treats identical or already-canonicalized paths as one identity value
fn equivalent_identity_path(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }

    left.canonicalize()
        .ok()
        .zip(right.canonicalize().ok())
        .is_some_and(|(left, right)| left == right)
}

/// Formats path sources without hiding which identity disagreed
fn format_identity_paths(paths: &[(String, PathBuf)]) -> String {
    paths
        .iter()
        .map(|(source, path)| format!("{source}={}", path.display()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Extracts an application identifier from a compatdata directory
fn steam_app_id_from_compatdata_dir(path: &Path) -> Option<u32> {
    path.file_name()?.to_str()?.parse().ok()
}
