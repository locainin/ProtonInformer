//! Steam library, game, and Proton prefix discovery.
//!
//! Discovery returns warnings alongside successful games. Broken manifests and
//! unreadable libraries must remain visible to users instead of disappearing
//! from the result set.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SteamGame {
    pub app_id: u32,
    pub name: String,
    pub install_dir: String,
    pub library_root: PathBuf,
    pub game_dir: PathBuf,
    pub game_dir_exists: bool,
    pub compatdata_dir: PathBuf,
    pub proton_prefix: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryWarning {
    pub path: PathBuf,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SteamDiscoveryReport {
    pub games: Vec<SteamGame>,
    pub warnings: Vec<DiscoveryWarning>,
}

/// Discovers every readable app manifest and retains all parse failures.
#[must_use]
pub fn discover_games() -> SteamDiscoveryReport {
    let mut games = Vec::new();
    let mut warnings = Vec::new();

    for library in discover_libraries() {
        let steamapps = library.join("steamapps");
        let entries = match fs::read_dir(&steamapps) {
            Ok(entries) => entries,
            Err(source) => {
                warnings.push(DiscoveryWarning {
                    path: steamapps,
                    message: source.to_string(),
                });
                continue;
            }
        };

        // App manifests are the source of truth for names and install folders.
        for manifest in entries.flatten().map(|entry| entry.path()).filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.starts_with("appmanifest_")
                        && Path::new(name)
                            .extension()
                            .is_some_and(|extension| extension.eq_ignore_ascii_case("acf"))
                })
        }) {
            match parse_manifest(&manifest, &library) {
                Ok(game) => games.push(game),
                Err(error) => warnings.push(DiscoveryWarning {
                    path: manifest,
                    message: error.to_string(),
                }),
            }
        }
    }

    games.sort_by_key(|game| game.app_id);
    games.dedup_by_key(|game| game.app_id);
    SteamDiscoveryReport { games, warnings }
}

/// Returns candidate Steam libraries from native, Flatpak, XDG, and exported roots.
#[must_use]
pub fn discover_libraries() -> Vec<PathBuf> {
    let mut libraries = BTreeSet::new();

    for root in steam_roots() {
        if root.is_dir() {
            libraries.insert(root.clone());
        }

        let library_file = root.join("config/libraryfolders.vdf");
        let Ok(contents) = fs::read_to_string(&library_file) else {
            continue;
        };

        for line in contents.lines() {
            if let Some(path) = quoted_value(line, "path") {
                libraries.insert(PathBuf::from(path.replace("\\\\", "\\")));
            }
        }
    }

    libraries.into_iter().collect()
}

/// Finds one game while preserving warnings for caller diagnostics.
#[must_use]
pub fn find_game(app_id: u32) -> (Option<SteamGame>, Vec<DiscoveryWarning>) {
    let report = discover_games();
    let game = report.games.into_iter().find(|game| game.app_id == app_id);
    (game, report.warnings)
}

fn steam_roots() -> Vec<PathBuf> {
    let mut roots = BTreeSet::new();

    // Steam exports this root to compatibility-tool processes.
    if let Some(root) = env::var_os("STEAM_COMPAT_CLIENT_INSTALL_PATH") {
        roots.insert(PathBuf::from(root));
    }

    let home = env::var_os("HOME").map(PathBuf::from);
    let data_home = env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| home.as_ref().map(|path| path.join(".local/share")));

    if let Some(data_home) = data_home {
        roots.insert(data_home.join("Steam"));
    }
    if let Some(home) = home {
        roots.insert(home.join(".local/share/Steam"));
        roots.insert(home.join(".steam/steam"));
        roots.insert(home.join(".var/app/com.valvesoftware.Steam/.local/share/Steam"));
    }

    roots.into_iter().collect()
}

fn parse_manifest(path: &Path, library_root: &Path) -> Result<SteamGame> {
    let contents = fs::read_to_string(path).map_err(|source| Error::io(path, source))?;
    let app_id: u32 = required_value(&contents, path, "appid")?
        .parse()
        .map_err(|_| Error::SteamMetadata {
            path: path.to_path_buf(),
            reason: "appid is not an unsigned integer".into(),
        })?;
    let name = required_value(&contents, path, "name")?;
    let install_dir = required_value(&contents, path, "installdir")?;
    let game_dir = library_root.join("steamapps/common").join(&install_dir);
    let compatdata_dir = library_root
        .join("steamapps/compatdata")
        .join(app_id.to_string());
    let prefix = compatdata_dir.join("pfx");

    Ok(SteamGame {
        app_id,
        name,
        game_dir_exists: game_dir.is_dir(),
        game_dir,
        proton_prefix: prefix.is_dir().then_some(prefix),
        compatdata_dir,
        install_dir,
        library_root: library_root.to_path_buf(),
    })
}

fn required_value(contents: &str, path: &Path, key: &str) -> Result<String> {
    contents
        .lines()
        .find_map(|line| quoted_value(line, key))
        .ok_or_else(|| Error::SteamMetadata {
            path: path.to_path_buf(),
            reason: format!("missing quoted {key} field"),
        })
}

fn quoted_value(line: &str, key: &str) -> Option<String> {
    // Valve's text format permits nested blocks, but these fields are complete
    // quoted key/value pairs and do not require a lossy whole-file parser.
    let mut quoted = line.split('"').skip(1).step_by(2);
    let found_key = quoted.next()?.trim();
    let value = quoted.next()?;
    found_key
        .eq_ignore_ascii_case(key)
        .then(|| value.to_owned())
}
