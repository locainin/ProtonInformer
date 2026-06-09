//! Steam discovery invariants.

use proton_informer::steam;

#[test]
fn discovered_games_are_sorted_and_unique() {
    let report = steam::discover_games();
    let app_ids: Vec<u32> = report.games.iter().map(|game| game.app_id).collect();
    let mut expected = app_ids.clone();
    expected.sort_unstable();
    expected.dedup();

    assert_eq!(app_ids, expected);
}

#[test]
fn reported_prefixes_exist() {
    let report = steam::discover_games();

    assert!(report.games.iter().all(|game| {
        game.proton_prefix
            .as_deref()
            .is_none_or(std::path::Path::is_dir)
    }));
}
