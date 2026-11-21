package inject

import (
	"regexp"

	"github.com/dhruv29/vajra/internal/probe"
)

// signature is text only a particular database engine writes when it fails
// to parse a query. Generic words like "SQL" or "error" are deliberately not
// here: they appear on ordinary pages and would make false positives.
type signature struct {
	database string
	pattern  *regexp.Regexp
}

var signatures = []signature{
	{"MySQL/MariaDB", regexp.MustCompile(`(?i)you have an error in your SQL syntax`)},
	{"MySQL/MariaDB", regexp.MustCompile(`(?i)check the manual that (?:corresponds to|fits) your (?:MySQL|MariaDB) server version`)},
	{"MySQL/MariaDB", regexp.MustCompile(`(?i)warning: mysqli?_[a-z_]+\(\)`)},
	{"MySQL/MariaDB", regexp.MustCompile(`com\.mysql\.jdbc|MySqlException`)},
	{"PostgreSQL", regexp.MustCompile(`(?i)unterminated quoted string at or near`)},
	{"PostgreSQL", regexp.MustCompile(`ERROR:\s+syntax error at or near`)},
	{"PostgreSQL", regexp.MustCompile(`PG::SyntaxError|org\.postgresql\.util\.PSQLException|pg_(?:query|exec)\(\): Query failed`)},
	{"SQLite", regexp.MustCompile(`SQLITE_ERROR|SQLite3::SQLException|sqlite3\.OperationalError|System\.Data\.SQLite\.SQLiteException`)},
	{"SQLite", regexp.MustCompile(`unrecognized token: "`)},
	{"SQLite", regexp.MustCompile(`near "[^"\n]{1,60}": syntax error`)},
	{"MSSQL", regexp.MustCompile(`(?i)unclosed quotation mark after the character string`)},
	{"MSSQL", regexp.MustCompile(`Microsoft OLE DB Provider for SQL Server|\[Microsoft\]\[ODBC SQL Server Driver\]`)},
	{"MSSQL", regexp.MustCompile(`(?:System|Microsoft)\.Data\.SqlClient\.SqlException`)},
	{"Oracle", regexp.MustCompile(`\bORA-\d{5}\b`)},
	{"Oracle", regexp.MustCompile(`(?i)quoted string not properly terminated`)},
}

// dbError is a database error signature found in a response body.
type dbError struct {
	database string
	matched  string
	// at is the byte offset of the match in the body.
	at int
}

// findDBError returns the first signature found in body, in table order.
func findDBError(body string) (dbError, bool) {
	for _, s := range signatures {
		if loc := s.pattern.FindStringIndex(body); loc != nil {
			return dbError{database: s.database, matched: body[loc[0]:loc[1]], at: loc[0]}, true
		}
	}
	return dbError{}, false
}

// judgeSQL applies the SQL-error proof rule. All three responses must come
// from the target; the value with one added quote must produce a database
// error signature; and neither the original value nor the value with a
// doubled quote may produce any signature at all. A doubled quote is how SQL
// escapes a quote, so an error that comes and goes with the quote's balance
// points at the quote reaching a query unescaped. A baseline or doubled-quote
// body that was cut short could hide a signature, so it disqualifies.
func judgeSQL(baseline, quote, doubled probe.Response) (dbError, bool) {
	for _, r := range []probe.Response{baseline, quote, doubled} {
		if !r.Answered() {
			return dbError{}, false
		}
	}
	if baseline.BodyTruncated || doubled.BodyTruncated {
		return dbError{}, false
	}
	if _, found := findDBError(baseline.Body); found {
		return dbError{}, false
	}
	if _, found := findDBError(doubled.Body); found {
		return dbError{}, false
	}
	return findDBError(quote.Body)
}
