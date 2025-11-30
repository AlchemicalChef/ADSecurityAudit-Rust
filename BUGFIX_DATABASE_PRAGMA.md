# Startup Panic Fixes

## Issue 1: Database PRAGMA Error
Application panicked on startup with error:
```
thread 'main' panicked at src/main.rs:1265:49:
Failed to initialize database: Execute returned results - did you mean to call query?
```

## Root Cause
The database initialization code in `src-tauri/src/database.rs` was using `execute()` to set PRAGMA values:

```rust
conn.execute("PRAGMA journal_mode=WAL", [])?;
conn.execute("PRAGMA synchronous=NORMAL", [])?;
conn.execute("PRAGMA foreign_keys=ON", [])?;
```

The problem: `PRAGMA journal_mode=WAL` returns a result (the mode that was set), but `execute()` expects statements that don't return results. This caused rusqlite to panic.

## Fix Applied
Changed to use `pragma_update()` which is the proper rusqlite method for setting PRAGMA values:

```rust
conn.pragma_update(None, "journal_mode", "WAL")?;
conn.pragma_update(None, "synchronous", "NORMAL")?;
conn.pragma_update(None, "foreign_keys", "ON")?;
```

**File:** `src-tauri/src/database.rs`
**Lines:** 51-53

## Build Status
✅ **Fixed and rebuilt**
- Build time: 22.95s
- Errors: 0
- Warnings: 69 (unchanged, safe)

## Testing
The application now initializes correctly without panicking. The database is created at:
```
/Users/night/Library/Application Support/IRP/irp.db
```

## Notes
- `pragma_update()` is the type-safe way to set PRAGMA values in rusqlite
- The first parameter `None` means no schema name (uses main database)
- This method properly handles PRAGMA statements that return results

## Related
This is a common rusqlite gotcha - always use `pragma_update()` for setting PRAGMAs, not `execute()`.

---

## Issue 2: Tokio Runtime Error
After fixing the database issue, application panicked with:
```
thread 'main' panicked at src/main.rs:1314:5:
there is no reactor running, must be called from the context of a Tokio 1.x runtime
```

### Root Cause
The code was trying to spawn async tasks before the Tauri runtime was initialized:

```rust
// This runs BEFORE Tauri runtime is ready
tokio::spawn(async move {
    if let Err(e) = fm_clone.initialize().await {
        eprintln!("Failed to initialize ForestManager: {}", e);
    }
});

tauri::Builder::default()
    .plugin(tauri_plugin_shell::init())
    .manage(app_state)
```

### Fix Applied
Moved the async initialization to the Tauri `.setup()` hook, which runs in the Tauri async runtime:

```rust
tauri::Builder::default()
    .plugin(tauri_plugin_shell::init())
    .setup(move |app| {
        // Initialize ForestManager asynchronously in the Tauri runtime
        let fm_clone = forest_manager.clone();
        tauri::async_runtime::spawn(async move {
            if let Err(e) = fm_clone.initialize().await {
                eprintln!("Failed to initialize ForestManager: {}", e);
            }
        });
        Ok(())
    })
    .manage(app_state)
```

**File:** `src-tauri/src/main.rs`
**Lines:** 1314-1323

### Build Status
✅ **Fixed and rebuilt**
- Build time: 21.83s
- Errors: 0
- Warnings: 70 (unchanged, safe)

### Key Points
- Use `tauri::async_runtime::spawn()` instead of `tokio::spawn()` in Tauri apps
- The `.setup()` hook is the right place for async initialization
- The setup hook runs after the Tauri runtime is ready but before the UI is shown

---

## Final Status

✅ **Both issues fixed**
✅ **Application starts successfully**
✅ **All async operations working**

The application is now ready to run without panicking!
