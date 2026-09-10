//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// V1.8.0 uses Windows' built-in WinSQLite3 component. This keeps the program
// a single Windows x64 EXE and avoids installing Access, SQL Server, a SQLite
// service, or a separate SQLite DLL on supported Windows Server versions.

const (
	sqliteOK   = 0
	sqliteRow  = 100
	sqliteDone = 101

	sqliteOpenReadWrite = 0x00000002
	sqliteOpenCreate    = 0x00000004
	sqliteOpenFullMutex = 0x00010000
)

var (
	winSQLiteDLL = syscall.NewLazyDLL("winsqlite3.dll")

	procSQLiteOpenV2      = winSQLiteDLL.NewProc("sqlite3_open_v2")
	procSQLiteCloseV2     = winSQLiteDLL.NewProc("sqlite3_close_v2")
	procSQLiteErrMsg      = winSQLiteDLL.NewProc("sqlite3_errmsg")
	procSQLiteExec        = winSQLiteDLL.NewProc("sqlite3_exec")
	procSQLitePrepareV2   = winSQLiteDLL.NewProc("sqlite3_prepare_v2")
	procSQLiteStep        = winSQLiteDLL.NewProc("sqlite3_step")
	procSQLiteFinalize    = winSQLiteDLL.NewProc("sqlite3_finalize")
	procSQLiteReset       = winSQLiteDLL.NewProc("sqlite3_reset")
	procSQLiteClearBind   = winSQLiteDLL.NewProc("sqlite3_clear_bindings")
	procSQLiteBindText    = winSQLiteDLL.NewProc("sqlite3_bind_text")
	procSQLiteBindInt64   = winSQLiteDLL.NewProc("sqlite3_bind_int64")
	procSQLiteBindNull    = winSQLiteDLL.NewProc("sqlite3_bind_null")
	procSQLiteColumnText  = winSQLiteDLL.NewProc("sqlite3_column_text")
	procSQLiteColumnBytes = winSQLiteDLL.NewProc("sqlite3_column_bytes")
	procSQLiteColumnInt64 = winSQLiteDLL.NewProc("sqlite3_column_int64")
	procSQLiteBusyTimeout = winSQLiteDLL.NewProc("sqlite3_busy_timeout")
)

type winSQLite struct {
	mu sync.Mutex
	h  uintptr
}

type winStmt struct {
	db *winSQLite
	h  uintptr
}

var (
	sqliteDB      *winSQLite
	sqliteDBPath  string
	sqlitePrimary bool
	sqliteMu      sync.RWMutex
)

const sqliteSchemaVersion = 1

func sqliteIsPrimary() bool {
	sqliteMu.RLock()
	defer sqliteMu.RUnlock()
	return sqlitePrimary && sqliteDB != nil
}

func setSQLitePrimary(v bool) {
	sqliteMu.Lock()
	sqlitePrimary = v
	sqliteMu.Unlock()
}

func cBytes(s string) []byte {
	b := make([]byte, len(s)+1)
	copy(b, s)
	return b
}

func ptrOfBytes(b []byte) uintptr {
	if len(b) == 0 {
		return 0
	}
	return uintptr(unsafe.Pointer(&b[0]))
}

func readCString(p uintptr, max int) string {
	if p == 0 || max <= 0 {
		return ""
	}
	b := unsafe.Slice((*byte)(unsafe.Pointer(p)), max)
	n := 0
	for n < len(b) && b[n] != 0 {
		n++
	}
	return string(b[:n])
}

func (db *winSQLite) errMessage() string {
	if db == nil || db.h == 0 {
		return "SQLite error"
	}
	p, _, _ := procSQLiteErrMsg.Call(db.h)
	msg := readCString(p, 4096)
	if msg == "" {
		return "SQLite error"
	}
	return msg
}

func sqliteRCError(db *winSQLite, op string, rc uintptr) error {
	msg := "SQLite error"
	if db != nil {
		msg = db.errMessage()
	}
	return fmt.Errorf("%s failed (rc=%d): %s", op, rc, msg)
}

func openWinSQLite(path string) (*winSQLite, error) {
	if err := winSQLiteDLL.Load(); err != nil {
		return nil, fmt.Errorf("load winsqlite3.dll: %w", err)
	}
	// Resolve the core entry points now so a missing/incompatible DLL causes a
	// clean JSON fallback instead of a late crash.
	required := []*syscall.LazyProc{
		procSQLiteOpenV2, procSQLiteCloseV2, procSQLiteErrMsg, procSQLiteExec,
		procSQLitePrepareV2, procSQLiteStep, procSQLiteFinalize, procSQLiteReset, procSQLiteClearBind,
		procSQLiteBindText, procSQLiteBindInt64, procSQLiteBindNull,
		procSQLiteColumnText, procSQLiteColumnBytes, procSQLiteColumnInt64,
		procSQLiteBusyTimeout,
	}
	for _, p := range required {
		if err := p.Find(); err != nil {
			return nil, fmt.Errorf("resolve WinSQLite3 API %s: %w", p.Name, err)
		}
	}

	name := cBytes(path)
	var handle uintptr
	flags := uintptr(sqliteOpenReadWrite | sqliteOpenCreate | sqliteOpenFullMutex)
	rc, _, _ := procSQLiteOpenV2.Call(ptrOfBytes(name), uintptr(unsafe.Pointer(&handle)), flags, 0)
	runtime.KeepAlive(name)
	if rc != sqliteOK || handle == 0 {
		if handle != 0 {
			procSQLiteCloseV2.Call(handle)
		}
		return nil, fmt.Errorf("sqlite3_open_v2 failed (rc=%d)", rc)
	}
	db := &winSQLite{h: handle}
	procSQLiteBusyTimeout.Call(db.h, 5000)
	return db, nil
}

func (db *winSQLite) close() {
	if db == nil {
		return
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.h != 0 {
		procSQLiteCloseV2.Call(db.h)
		db.h = 0
	}
}

func (db *winSQLite) execUnlocked(sqlText string) error {
	sqlb := cBytes(sqlText)
	rc, _, _ := procSQLiteExec.Call(db.h, ptrOfBytes(sqlb), 0, 0, 0)
	runtime.KeepAlive(sqlb)
	if rc != sqliteOK {
		return sqliteRCError(db, "sqlite3_exec", rc)
	}
	return nil
}

func (db *winSQLite) exec(sqlText string) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.execUnlocked(sqlText)
}

func (db *winSQLite) prepareUnlocked(sqlText string) (*winStmt, error) {
	sqlb := cBytes(sqlText)
	var stmt uintptr
	rc, _, _ := procSQLitePrepareV2.Call(db.h, ptrOfBytes(sqlb), ^uintptr(0), uintptr(unsafe.Pointer(&stmt)), 0)
	runtime.KeepAlive(sqlb)
	if rc != sqliteOK || stmt == 0 {
		return nil, sqliteRCError(db, "sqlite3_prepare_v2", rc)
	}
	return &winStmt{db: db, h: stmt}, nil
}

func (s *winStmt) finalize() {
	if s != nil && s.h != 0 {
		procSQLiteFinalize.Call(s.h)
		s.h = 0
	}
}

func (s *winStmt) reset() error {
	rc, _, _ := procSQLiteReset.Call(s.h)
	if rc != sqliteOK {
		return sqliteRCError(s.db, "sqlite3_reset", rc)
	}
	rc, _, _ = procSQLiteClearBind.Call(s.h)
	if rc != sqliteOK {
		return sqliteRCError(s.db, "sqlite3_clear_bindings", rc)
	}
	return nil
}

func (s *winStmt) bind(index int, value interface{}) error {
	var rc uintptr
	switch v := value.(type) {
	case nil:
		rc, _, _ = procSQLiteBindNull.Call(s.h, uintptr(index))
	case string:
		n := len(v)
		b := []byte(v)
		if len(b) == 0 {
			// A NULL pointer means SQL NULL. Keep a real pointer for empty TEXT.
			b = []byte{0}
		}
		p := uintptr(unsafe.Pointer(&b[0]))
		// SQLITE_TRANSIENT == (sqlite3_destructor_type)-1, so SQLite copies the
		// Go bytes before this call returns.
		rc, _, _ = procSQLiteBindText.Call(s.h, uintptr(index), p, uintptr(n), ^uintptr(0))
		runtime.KeepAlive(b)
	case int:
		rc, _, _ = procSQLiteBindInt64.Call(s.h, uintptr(index), uintptr(int64(v)))
	case int64:
		rc, _, _ = procSQLiteBindInt64.Call(s.h, uintptr(index), uintptr(v))
	case bool:
		n := int64(0)
		if v {
			n = 1
		}
		rc, _, _ = procSQLiteBindInt64.Call(s.h, uintptr(index), uintptr(n))
	default:
		txt := fmt.Sprint(v)
		n := len(txt)
		b := []byte(txt)
		if len(b) == 0 {
			b = []byte{0}
		}
		p := uintptr(unsafe.Pointer(&b[0]))
		rc, _, _ = procSQLiteBindText.Call(s.h, uintptr(index), p, uintptr(n), ^uintptr(0))
		runtime.KeepAlive(b)
	}
	if rc != sqliteOK {
		return sqliteRCError(s.db, fmt.Sprintf("sqlite3_bind(%d)", index), rc)
	}
	return nil
}

func (s *winStmt) bindAll(args []interface{}) error {
	for i, a := range args {
		if err := s.bind(i+1, a); err != nil {
			return err
		}
	}
	return nil
}

func (s *winStmt) step() (uintptr, error) {
	rc, _, _ := procSQLiteStep.Call(s.h)
	if rc != sqliteRow && rc != sqliteDone {
		return rc, sqliteRCError(s.db, "sqlite3_step", rc)
	}
	return rc, nil
}

func (s *winStmt) columnText(col int) string {
	p, _, _ := procSQLiteColumnText.Call(s.h, uintptr(col))
	if p == 0 {
		return ""
	}
	n, _, _ := procSQLiteColumnBytes.Call(s.h, uintptr(col))
	if n == 0 {
		return ""
	}
	b := unsafe.Slice((*byte)(unsafe.Pointer(p)), int(n))
	return string(b)
}

func (s *winStmt) columnInt64(col int) int64 {
	v, _, _ := procSQLiteColumnInt64.Call(s.h, uintptr(col))
	return int64(v)
}

func (db *winSQLite) execPreparedUnlocked(sqlText string, args ...interface{}) error {
	stmt, err := db.prepareUnlocked(sqlText)
	if err != nil {
		return err
	}
	defer stmt.finalize()
	if err := stmt.bindAll(args); err != nil {
		return err
	}
	rc, err := stmt.step()
	if err != nil {
		return err
	}
	if rc != sqliteDone {
		return fmt.Errorf("SQLite statement did not finish")
	}
	return nil
}

func (db *winSQLite) execPrepared(sqlText string, args ...interface{}) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.execPreparedUnlocked(sqlText, args...)
}

func (db *winSQLite) withTransaction(fn func() error) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if err := db.execUnlocked("BEGIN IMMEDIATE"); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = db.execUnlocked("ROLLBACK")
		}
	}()
	if err := fn(); err != nil {
		return err
	}
	if err := db.execUnlocked("COMMIT"); err != nil {
		return err
	}
	committed = true
	return nil
}

func (db *winSQLite) queryRows(sqlText string, args []interface{}, rowFn func(*winStmt) error) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	stmt, err := db.prepareUnlocked(sqlText)
	if err != nil {
		return err
	}
	defer stmt.finalize()
	if err := stmt.bindAll(args); err != nil {
		return err
	}
	for {
		rc, err := stmt.step()
		if err != nil {
			return err
		}
		if rc == sqliteDone {
			return nil
		}
		if err := rowFn(stmt); err != nil {
			return err
		}
	}
}

func (db *winSQLite) queryOneInt(sqlText string, args ...interface{}) (int, error) {
	n := 0
	found := false
	err := db.queryRows(sqlText, args, func(s *winStmt) error {
		if !found {
			n = int(s.columnInt64(0))
			found = true
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if !found {
		return 0, fmt.Errorf("SQLite query returned no row")
	}
	return n, nil
}

func (db *winSQLite) queryOneText(sqlText string, args ...interface{}) (string, bool, error) {
	var out string
	found := false
	err := db.queryRows(sqlText, args, func(s *winStmt) error {
		if !found {
			out = s.columnText(0)
			found = true
		}
		return nil
	})
	return out, found, err
}

func initSQLiteStorage(path string) error {
	sqliteDBPath = path
	db, err := openWinSQLite(path)
	if err != nil {
		return err
	}

	pragmas := []string{
		`PRAGMA journal_mode=WAL`,
		`PRAGMA synchronous=NORMAL`,
		`PRAGMA foreign_keys=ON`,
		`PRAGMA temp_store=MEMORY`,
	}
	for _, p := range pragmas {
		if err := db.exec(p); err != nil {
			db.close()
			return fmt.Errorf("sqlite pragma failed: %w", err)
		}
	}

	schema := []string{
		`CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS devices (mac TEXT PRIMARY KEY, data_json TEXT NOT NULL, updated_at TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, data_json TEXT NOT NULL, updated_at TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT NOT NULL, username TEXT NOT NULL, action TEXT NOT NULL, mac TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '', client_ip TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE IF NOT EXISTS recycle_bin (id INTEGER PRIMARY KEY AUTOINCREMENT, deleted_at TEXT NOT NULL, mac TEXT NOT NULL DEFAULT '', data_json TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_time ON audit_logs(time)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_username ON audit_logs(username)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_mac ON audit_logs(mac)`,
		`CREATE INDEX IF NOT EXISTS idx_recycle_bin_mac ON recycle_bin(mac)`,
	}
	for _, stmt := range schema {
		if err := db.exec(stmt); err != nil {
			db.close()
			return fmt.Errorf("sqlite schema failed: %w", err)
		}
	}
	sqliteDB = db
	return nil
}

func closeSQLiteStorage() {
	sqliteMu.Lock()
	db := sqliteDB
	sqliteDB = nil
	sqlitePrimary = false
	sqliteMu.Unlock()
	if db != nil {
		db.close()
	}
}

func sqliteMigrationComplete() bool {
	if sqliteDB == nil {
		return false
	}
	v, found, err := sqliteDB.queryOneText(`SELECT value FROM meta WHERE key='migration_complete'`)
	return err == nil && found && v == "1"
}

func normalizeStateAfterLoad() {
	if state.Devices == nil {
		state.Devices = map[string]*Device{}
	}
	if state.Users == nil {
		state.Users = map[string]*User{}
	}
	if state.Audit == nil {
		state.Audit = []Audit{}
	}
	if state.RecycleBin == nil {
		state.RecycleBin = []DeletedDevice{}
	}
	for mac, d := range state.Devices {
		if d == nil {
			delete(state.Devices, mac)
			continue
		}
		if d.ActiveLeases == nil {
			d.ActiveLeases = []LeaseSnapshot{}
		}
		if d.OnlineDates == nil {
			d.OnlineDates = []string{}
		}
		if d.MultiLease.Observations == nil {
			d.MultiLease.Observations = []LeaseObservation{}
		}
		if d.MultiLease.StaleIPs == nil {
			d.MultiLease.StaleIPs = []string{}
		}
	}
	for _, u := range state.Users {
		u.Role = strings.ToLower(strings.TrimSpace(u.Role))
		if u.Role != "admin" && u.Role != "operator" && u.Role != "viewer" {
			u.Role = "viewer"
		}
	}
}

func loadStateFromSQLite() error {
	if sqliteDB == nil {
		return fmt.Errorf("sqlite is not initialized")
	}
	loaded := Persist{Devices: map[string]*Device{}, Users: map[string]*User{}, Audit: []Audit{}, RecycleBin: []DeletedDevice{}}

	if err := sqliteDB.queryRows(`SELECT mac, data_json FROM devices ORDER BY mac`, nil, func(s *winStmt) error {
		mac := s.columnText(0)
		raw := s.columnText(1)
		var d Device
		if err := json.Unmarshal([]byte(raw), &d); err != nil {
			return fmt.Errorf("decode device %s: %w", mac, err)
		}
		if d.MAC == "" {
			d.MAC = mac
		}
		loaded.Devices[mac] = &d
		return nil
	}); err != nil {
		return err
	}

	if err := sqliteDB.queryRows(`SELECT username, data_json FROM users ORDER BY username`, nil, func(s *winStmt) error {
		username := s.columnText(0)
		raw := s.columnText(1)
		var u User
		if err := json.Unmarshal([]byte(raw), &u); err != nil {
			return fmt.Errorf("decode user %s: %w", username, err)
		}
		if u.Username == "" {
			u.Username = username
		}
		loaded.Users[username] = &u
		return nil
	}); err != nil {
		return err
	}

	if err := sqliteDB.queryRows(`SELECT data_json FROM recycle_bin ORDER BY id`, nil, func(s *winStmt) error {
		raw := s.columnText(0)
		var x DeletedDevice
		if err := json.Unmarshal([]byte(raw), &x); err != nil {
			return fmt.Errorf("decode recycle entry: %w", err)
		}
		loaded.RecycleBin = append(loaded.RecycleBin, x)
		return nil
	}); err != nil {
		return err
	}

	// Audit logs are queried from SQLite with LIMIT/OFFSET and are intentionally
	// not loaded into RAM at startup.
	state = loaded
	normalizeStateAfterLoad()
	return nil
}

func createMigrationBackup() string {
	root := filepath.Join(baseDir, "backup")
	dir := filepath.Join(root, "before_sqlite_"+time.Now().Format("20060102_150405"))
	if err := os.MkdirAll(dir, 0700); err != nil {
		return ""
	}
	copyFileIfExists(dataPath, filepath.Join(dir, filepath.Base(dataPath)))
	copyFileIfExists(filepath.Join(baseDir, "config.json"), filepath.Join(dir, "config.json"))
	return dir
}

func migrateCurrentStateToSQLite() error {
	if sqliteDB == nil {
		return fmt.Errorf("sqlite is not initialized")
	}
	backupDir := createMigrationBackup()
	expectedDevices := len(state.Devices)
	expectedUsers := len(state.Users)
	expectedAudit := len(state.Audit)
	expectedRecycle := len(state.RecycleBin)

	err := sqliteDB.withTransaction(func() error {
		if err := sqliteDB.execUnlocked(`DELETE FROM devices`); err != nil {
			return err
		}
		if err := sqliteDB.execUnlocked(`DELETE FROM users`); err != nil {
			return err
		}
		if err := sqliteDB.execUnlocked(`DELETE FROM audit_logs`); err != nil {
			return err
		}
		if err := sqliteDB.execUnlocked(`DELETE FROM recycle_bin`); err != nil {
			return err
		}

		dstmt, err := sqliteDB.prepareUnlocked(`INSERT INTO devices(mac,data_json,updated_at) VALUES(?,?,?)`)
		if err != nil {
			return err
		}
		for mac, d := range state.Devices {
			b, err := json.Marshal(d)
			if err != nil {
				dstmt.finalize()
				return err
			}
			if err := dstmt.bindAll([]interface{}{mac, string(b), d.UpdatedAt}); err != nil {
				dstmt.finalize()
				return err
			}
			rc, err := dstmt.step()
			if err != nil || rc != sqliteDone {
				dstmt.finalize()
				if err != nil {
					return err
				}
				return fmt.Errorf("device insert did not finish")
			}
			if err := dstmt.reset(); err != nil {
				dstmt.finalize()
				return err
			}
		}
		dstmt.finalize()

		ustmt, err := sqliteDB.prepareUnlocked(`INSERT INTO users(username,data_json,updated_at) VALUES(?,?,?)`)
		if err != nil {
			return err
		}
		for username, u := range state.Users {
			b, err := json.Marshal(u)
			if err != nil {
				ustmt.finalize()
				return err
			}
			if err := ustmt.bindAll([]interface{}{username, string(b), u.CreatedAt}); err != nil {
				ustmt.finalize()
				return err
			}
			rc, err := ustmt.step()
			if err != nil || rc != sqliteDone {
				ustmt.finalize()
				if err != nil {
					return err
				}
				return fmt.Errorf("user insert did not finish")
			}
			if err := ustmt.reset(); err != nil {
				ustmt.finalize()
				return err
			}
		}
		ustmt.finalize()

		astmt, err := sqliteDB.prepareUnlocked(`INSERT INTO audit_logs(time,username,action,mac,detail,client_ip) VALUES(?,?,?,?,?,?)`)
		if err != nil {
			return err
		}
		for _, a := range state.Audit {
			if err := astmt.bindAll([]interface{}{a.Time, a.Username, a.Action, a.MAC, a.Detail, a.ClientIP}); err != nil {
				astmt.finalize()
				return err
			}
			rc, err := astmt.step()
			if err != nil || rc != sqliteDone {
				astmt.finalize()
				if err != nil {
					return err
				}
				return fmt.Errorf("audit insert did not finish")
			}
			if err := astmt.reset(); err != nil {
				astmt.finalize()
				return err
			}
		}
		astmt.finalize()

		rstmt, err := sqliteDB.prepareUnlocked(`INSERT INTO recycle_bin(deleted_at,mac,data_json) VALUES(?,?,?)`)
		if err != nil {
			return err
		}
		for _, x := range state.RecycleBin {
			b, err := json.Marshal(x)
			if err != nil {
				rstmt.finalize()
				return err
			}
			if err := rstmt.bindAll([]interface{}{x.DeletedAt, x.Snapshot.MAC, string(b)}); err != nil {
				rstmt.finalize()
				return err
			}
			rc, err := rstmt.step()
			if err != nil || rc != sqliteDone {
				rstmt.finalize()
				if err != nil {
					return err
				}
				return fmt.Errorf("recycle insert did not finish")
			}
			if err := rstmt.reset(); err != nil {
				rstmt.finalize()
				return err
			}
		}
		rstmt.finalize()

		// Verify row counts before marking the migration complete. This is the
		// guard that prevents a partial migration from becoming primary storage.
		countUnlocked := func(table string) (int, error) {
			stmt, err := sqliteDB.prepareUnlocked(`SELECT COUNT(*) FROM ` + table)
			if err != nil {
				return 0, err
			}
			defer stmt.finalize()
			rc, err := stmt.step()
			if err != nil {
				return 0, err
			}
			if rc != sqliteRow {
				return 0, fmt.Errorf("count %s returned no row", table)
			}
			return int(stmt.columnInt64(0)), nil
		}
		dc, err := countUnlocked("devices")
		if err != nil {
			return err
		}
		uc, err := countUnlocked("users")
		if err != nil {
			return err
		}
		ac, err := countUnlocked("audit_logs")
		if err != nil {
			return err
		}
		rcCount, err := countUnlocked("recycle_bin")
		if err != nil {
			return err
		}
		if dc != expectedDevices || uc != expectedUsers || ac != expectedAudit || rcCount != expectedRecycle {
			return fmt.Errorf("migration verification failed: devices %d/%d users %d/%d audit %d/%d recycle %d/%d", dc, expectedDevices, uc, expectedUsers, ac, expectedAudit, rcCount, expectedRecycle)
		}

		meta := [][2]string{
			{"schema_version", fmt.Sprint(sqliteSchemaVersion)},
			{"migration_complete", "1"},
			{"migrated_at", nowISO()},
			{"source", "dhcp_monitor_data.json"},
			{"migration_backup", backupDir},
		}
		for _, kv := range meta {
			if err := sqliteDB.execPreparedUnlocked(`INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)`, kv[0], kv[1]); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	setSQLitePrimary(true)
	// History remains in audit_logs; freeing this slice avoids carrying a large
	// JSON audit history in RAM after migration.
	state.Audit = []Audit{}
	return nil
}

func saveCoreStateSQLiteLocked() error {
	if sqliteDB == nil {
		return fmt.Errorf("sqlite is not initialized")
	}
	pendingAudit := append([]Audit(nil), state.Audit...)
	err := sqliteDB.withTransaction(func() error {
		if err := sqliteDB.execUnlocked(`DELETE FROM devices`); err != nil {
			return err
		}
		dstmt, err := sqliteDB.prepareUnlocked(`INSERT INTO devices(mac,data_json,updated_at) VALUES(?,?,?)`)
		if err != nil {
			return err
		}
		for mac, d := range state.Devices {
			b, err := json.Marshal(d)
			if err != nil {
				dstmt.finalize()
				return err
			}
			if err := dstmt.bindAll([]interface{}{mac, string(b), d.UpdatedAt}); err != nil {
				dstmt.finalize()
				return err
			}
			rc, err := dstmt.step()
			if err != nil {
				dstmt.finalize()
				return err
			}
			if rc != sqliteDone {
				dstmt.finalize()
				return fmt.Errorf("device save did not finish")
			}
			if err := dstmt.reset(); err != nil {
				dstmt.finalize()
				return err
			}
		}
		dstmt.finalize()

		if err := sqliteDB.execUnlocked(`DELETE FROM users`); err != nil {
			return err
		}
		ustmt, err := sqliteDB.prepareUnlocked(`INSERT INTO users(username,data_json,updated_at) VALUES(?,?,?)`)
		if err != nil {
			return err
		}
		for username, u := range state.Users {
			b, err := json.Marshal(u)
			if err != nil {
				ustmt.finalize()
				return err
			}
			if err := ustmt.bindAll([]interface{}{username, string(b), u.CreatedAt}); err != nil {
				ustmt.finalize()
				return err
			}
			rc, err := ustmt.step()
			if err != nil {
				ustmt.finalize()
				return err
			}
			if rc != sqliteDone {
				ustmt.finalize()
				return fmt.Errorf("user save did not finish")
			}
			if err := ustmt.reset(); err != nil {
				ustmt.finalize()
				return err
			}
		}
		ustmt.finalize()

		if err := sqliteDB.execUnlocked(`DELETE FROM recycle_bin`); err != nil {
			return err
		}
		rstmt, err := sqliteDB.prepareUnlocked(`INSERT INTO recycle_bin(deleted_at,mac,data_json) VALUES(?,?,?)`)
		if err != nil {
			return err
		}
		for _, x := range state.RecycleBin {
			b, err := json.Marshal(x)
			if err != nil {
				rstmt.finalize()
				return err
			}
			if err := rstmt.bindAll([]interface{}{x.DeletedAt, x.Snapshot.MAC, string(b)}); err != nil {
				rstmt.finalize()
				return err
			}
			rc, err := rstmt.step()
			if err != nil {
				rstmt.finalize()
				return err
			}
			if rc != sqliteDone {
				rstmt.finalize()
				return fmt.Errorf("recycle save did not finish")
			}
			if err := rstmt.reset(); err != nil {
				rstmt.finalize()
				return err
			}
		}
		rstmt.finalize()

		// Legacy batch paths may append audit rows while holding the state lock.
		// Flush them in the same transaction so every delete/disable/release event
		// remains recoverable after switching to SQLite.
		if len(pendingAudit) > 0 {
			astmt, err := sqliteDB.prepareUnlocked(`INSERT INTO audit_logs(time,username,action,mac,detail,client_ip) VALUES(?,?,?,?,?,?)`)
			if err != nil {
				return err
			}
			for _, a := range pendingAudit {
				if err := astmt.bindAll([]interface{}{a.Time, a.Username, a.Action, a.MAC, a.Detail, a.ClientIP}); err != nil {
					astmt.finalize()
					return err
				}
				rc, err := astmt.step()
				if err != nil {
					astmt.finalize()
					return err
				}
				if rc != sqliteDone {
					astmt.finalize()
					return fmt.Errorf("pending audit save did not finish")
				}
				if err := astmt.reset(); err != nil {
					astmt.finalize()
					return err
				}
			}
			astmt.finalize()
		}
		return nil
	})
	if err == nil && len(pendingAudit) > 0 {
		state.Audit = state.Audit[len(pendingAudit):]
	}
	return err
}

func insertAuditSQLite(a Audit) error {
	if sqliteDB == nil {
		return fmt.Errorf("sqlite is not initialized")
	}
	return sqliteDB.execPrepared(`INSERT INTO audit_logs(time,username,action,mac,detail,client_ip) VALUES(?,?,?,?,?,?)`, a.Time, a.Username, a.Action, a.MAC, a.Detail, a.ClientIP)
}

func insertAuditRowsSQLite(rows []Audit) error {
	if len(rows) == 0 {
		return nil
	}
	if sqliteDB == nil {
		return fmt.Errorf("sqlite is not initialized")
	}
	return sqliteDB.withTransaction(func() error {
		stmt, err := sqliteDB.prepareUnlocked(`INSERT INTO audit_logs(time,username,action,mac,detail,client_ip) VALUES(?,?,?,?,?,?)`)
		if err != nil {
			return err
		}
		defer stmt.finalize()
		for _, a := range rows {
			if err := stmt.bindAll([]interface{}{a.Time, a.Username, a.Action, a.MAC, a.Detail, a.ClientIP}); err != nil {
				return err
			}
			rc, err := stmt.step()
			if err != nil {
				return err
			}
			if rc != sqliteDone {
				return fmt.Errorf("audit batch insert did not finish")
			}
			if err := stmt.reset(); err != nil {
				return err
			}
		}
		return nil
	})
}

func queryAuditSQLite(page, pageSize int, q string) ([]Audit, int, error) {
	if sqliteDB == nil {
		return nil, 0, fmt.Errorf("sqlite is not initialized")
	}
	where := ""
	args := []interface{}{}
	if strings.TrimSpace(q) != "" {
		pattern := "%" + strings.ToLower(strings.TrimSpace(q)) + "%"
		where = ` WHERE lower(username) LIKE ? OR lower(action) LIKE ? OR lower(mac) LIKE ? OR lower(detail) LIKE ? OR lower(client_ip) LIKE ?`
		for i := 0; i < 5; i++ {
			args = append(args, pattern)
		}
	}
	total, err := sqliteDB.queryOneInt(`SELECT COUNT(*) FROM audit_logs`+where, args...)
	if err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	qargs := append([]interface{}{}, args...)
	qargs = append(qargs, pageSize, offset)
	out := make([]Audit, 0, pageSize)
	err = sqliteDB.queryRows(`SELECT time,username,action,mac,detail,client_ip FROM audit_logs`+where+` ORDER BY id DESC LIMIT ? OFFSET ?`, qargs, func(s *winStmt) error {
		out = append(out, Audit{
			Time: s.columnText(0), Username: s.columnText(1), Action: s.columnText(2),
			MAC: s.columnText(3), Detail: s.columnText(4), ClientIP: s.columnText(5),
		})
		return nil
	})
	return out, total, err
}

func logStorageError(context string, err error) {
	if err != nil {
		log.Printf("[storage] %s: %v", context, err)
	}
}
