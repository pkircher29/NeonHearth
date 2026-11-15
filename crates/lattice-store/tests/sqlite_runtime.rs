use sqlx::Row;

#[tokio::test]
async fn bundled_sqlite_has_the_wal_page_size_memory_disclosure_fix() {
    let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
    let row = sqlx::query("SELECT sqlite_version() AS version")
        .fetch_one(&pool)
        .await
        .unwrap();
    let version: String = row.get("version");
    let parts: Vec<u32> = version
        .split('.')
        .map(|part| part.parse().unwrap())
        .collect();
    assert!(
        parts.as_slice() >= [3, 54, 0].as_slice(),
        "SQLite {version} predates RUSTSEC-2026-0459's fix"
    );
    pool.close().await;
}
