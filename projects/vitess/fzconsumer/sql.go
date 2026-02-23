// Copyright 2026 the cncf-fuzzing authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gofuzzheaders

import (
	"fmt"
	"strings"
)

// Vitess-aware SQL keywords. Includes standard MySQL keywords plus
// Vitess-specific ones (vschema, vindex, keyspaces, etc.).
var keywords = []string{
	"accessible", "action", "add", "after", "against", "algorithm",
	"all", "alter", "always", "analyze", "and", "as", "asc", "asensitive",
	"auto_increment", "avg_row_length", "before", "begin", "between",
	"bigint", "binary", "_binary", "_utf8mb4", "_utf8", "_latin1", "bit",
	"blob", "bool", "boolean", "both", "by", "call", "cancel", "cascade",
	"cascaded", "case", "cast", "channel", "change", "char", "character",
	"charset", "check", "checksum", "coalesce", "code", "collate", "collation",
	"column", "columns", "comment", "committed", "commit", "compact", "complete",
	"compressed", "compression", "condition", "connection", "constraint", "continue",
	"convert", "copy", "cume_dist", "substr", "substring", "create", "cross",
	"csv", "current_date", "current_time", "current_timestamp", "current_user",
	"cursor", "data", "database", "databases", "day", "day_hour", "day_microsecond",
	"day_minute", "day_second", "date", "datetime", "dec", "decimal", "declare",
	"default", "definer", "delay_key_write", "delayed", "delete", "dense_rank",
	"desc", "describe", "deterministic", "directory", "disable", "discard",
	"disk", "distinct", "distinctrow", "div", "double", "do", "drop", "dumpfile",
	"duplicate", "dynamic", "each", "else", "elseif", "empty", "enable",
	"enclosed", "encryption", "end", "enforced", "engine", "engines", "enum",
	"error", "escape", "escaped", "event", "exchange", "exclusive", "exists",
	"exit", "explain", "expansion", "export", "extended", "extract", "false",
	"fetch", "fields", "first", "first_value", "fixed", "float", "float4",
	"float8", "flush", "for", "force", "foreign", "format", "from", "full",
	"fulltext", "function", "general", "generated", "geometry", "geometrycollection",
	"get", "global", "gtid_executed", "grant", "group", "grouping", "groups",
	"group_concat", "having", "header", "high_priority", "hosts", "hour",
	"hour_microsecond", "hour_minute", "hour_second",
	"if", "ignore", "import", "in", "index", "indexes",
	"infile", "inout", "inner", "inplace", "insensitive", "insert", "insert_method",
	"int", "int1", "int2", "int3", "int4", "int8", "integer", "interval",
	"into", "io_after_gtids", "is", "isolation", "iterate", "invoker", "join",
	"json", "json_table", "key", "keys", "keyspaces", "key_block_size", "kill",
	"lag", "language", "last", "last_value", "last_insert_id", "lateral", "lead",
	"leading", "leave", "left", "less", "level", "like", "limit", "linear",
	"lines", "linestring", "load", "local", "localtime", "localtimestamp",
	"lock", "logs", "long", "longblob", "longtext", "loop", "low_priority",
	"manifest", "master_bind", "match", "max_rows", "maxvalue", "mediumblob",
	"mediumint", "mediumtext", "memory", "merge", "microsecond", "middleint",
	"min_rows", "minute", "minute_microsecond", "minute_second", "mod", "mode",
	"modify", "modifies", "multilinestring", "multipoint", "multipolygon",
	"month", "name", "names", "natural", "nchar", "next", "no", "none", "not",
	"no_write_to_binlog", "nth_value", "ntile", "null", "numeric", "of", "off",
	"offset", "on", "only", "open", "optimize", "optimizer_costs", "option",
	"optionally", "or", "order", "out", "outer", "outfile", "over", "overwrite",
	"pack_keys", "parser", "partition", "partitioning", "password", "percent_rank",
	"plugins", "point", "polygon", "precision", "primary", "privileges",
	"processlist", "procedure", "query", "quarter", "range", "rank", "read",
	"reads", "read_write", "real", "rebuild", "recursive", "redundant",
	"references", "regexp", "relay", "release", "remove", "rename", "reorganize",
	"repair", "repeat", "repeatable", "replace", "require", "resignal",
	"restrict", "return", "retry", "revert", "revoke", "right", "rlike",
	"rollback", "row", "row_format", "row_number", "rows", "s3", "savepoint",
	"schema", "schemas", "second", "second_microsecond", "security", "select",
	"sensitive", "separator", "sequence", "serializable", "session", "set",
	"share", "shared", "show", "signal", "signed", "slow", "smallint",
	"spatial", "specific", "sql", "sqlexception", "sqlstate", "sqlwarning",
	"sql_big_result", "sql_cache", "sql_calc_found_rows", "sql_no_cache",
	"sql_small_result", "ssl", "start", "starting", "stats_auto_recalc",
	"stats_persistent", "stats_sample_pages", "status", "storage", "stored",
	"straight_join", "stream", "system", "vstream",
	"table", "tables", "tablespace", "temporary", "temptable", "terminated",
	"text", "than", "then", "time", "timestamp", "timestampadd", "timestampdiff",
	"tinyblob", "tinyint", "tinytext", "to", "trailing", "transaction", "tree",
	"traditional", "trigger", "triggers", "true", "truncate", "uncommitted",
	"undefined", "undo", "union", "unique", "unlock", "unsigned", "update",
	"upgrade", "usage", "use", "user", "user_resources", "using", "utc_date",
	"utc_time", "utc_timestamp", "validation", "values", "variables", "varbinary",
	"varchar", "varcharacter", "varying", "vgtid_executed", "virtual", "vindex",
	"vindexes", "view", "vitess", "vitess_keyspaces", "vitess_metadata",
	"vitess_migration", "vitess_migrations", "vitess_replication_status",
	"vitess_shards", "vitess_tablets", "vschema", "warnings", "when",
	"where", "while", "window", "with", "without", "work", "write", "xor",
	"year", "year_month", "zerofill",
}

// needCustomString lists keywords that should be followed by a fuzz string
// argument when generating SQL statements.
var needCustomString = []string{
	"DISTINCTROW", "FROM",
	"GROUP BY", "HAVING", "WINDOW", "FOR",
	"ORDER BY", "LIMIT",
	"INTO", "PARTITION", "AS",
	"ON DUPLICATE KEY UPDATE",
	"WHERE", "LIMIT",
	"INFILE", "INTO TABLE", "CHARACTER SET",
	"TERMINATED BY", "ENCLOSED BY",
	"ESCAPED BY", "STARTING BY",
	"IGNORE",
	"VALUE", "VALUES",
	"SET",
	"ENGINE =",
	"DEFINER =", "ON SCHEDULE", "RENAME TO",
	"COMMENT", "DO", "INITIAL_SIZE = ", "OPTIONS",
	"ON", "USING", "JOIN",
}

func containsString(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Token sets for each SQL statement type
// ---------------------------------------------------------------------------

var selectTokens = [][]string{
	{"*", "CUSTOM_FUZZ_STRING", "DISTINCTROW"},
	{"HIGH_PRIORITY"},
	{"STRAIGHT_JOIN"},
	{"SQL_SMALL_RESULT", "SQL_BIG_RESULT", "SQL_BUFFER_RESULT"},
	{"SQL_NO_CACHE", "SQL_CALC_FOUND_ROWS"},
	{"CUSTOM_FUZZ_STRING"},
	{"FROM"},
	{"WHERE"},
	{"GROUP BY"},
	{"HAVING"},
	{"WINDOW"},
	{"ORDER BY"},
	{"LIMIT"},
	{"CUSTOM_FUZZ_STRING"},
	{"FOR"},
}

var insertTokens = [][]string{
	{"LOW_PRIORITY", "DELAYED", "HIGH_PRIORITY", "IGNORE"},
	{"INTO"},
	{"PARTITION"},
	{"CUSTOM_FUZZ_STRING"},
	{"AS"},
	{"ON DUPLICATE KEY UPDATE"},
}

var deleteTokens = [][]string{
	{"LOW_PRIORITY", "QUICK", "IGNORE", "FROM", "AS"},
	{"PARTITION"},
	{"WHERE"},
	{"ORDER BY"},
	{"LIMIT"},
}

var updateTokens = [][]string{
	{"LOW_PRIORITY", "IGNORE"},
	{"CUSTOM_FUZZ_STRING"},
	{"SET"},
	{"CUSTOM_FUZZ_STRING"},
	{"WHERE"},
	{"ORDER BY"},
	{"LIMIT"},
}

var loadTokens = [][]string{
	{"DATA"},
	{"LOW_PRIORITY", "CONCURRENT", "LOCAL"},
	{"INFILE"},
	{"REPLACE", "IGNORE"},
	{"INTO TABLE"},
	{"PARTITION"},
	{"CHARACTER SET"},
	{"FIELDS", "COLUMNS"},
	{"TERMINATED BY"},
	{"OPTIONALLY"},
	{"ENCLOSED BY"},
	{"ESCAPED BY"},
	{"LINES"},
	{"STARTING BY"},
	{"TERMINATED BY"},
	{"IGNORE"},
	{"LINES", "ROWS"},
	{"CUSTOM_FUZZ_STRING"},
}

var replaceTokens = [][]string{
	{"LOW_PRIORITY", "DELAYED"},
	{"INTO"},
	{"PARTITION"},
	{"CUSTOM_FUZZ_STRING"},
	{"VALUES", "VALUE"},
}

var createTokens = [][]string{
	{"OR REPLACE", "TEMPORARY", "UNDO"},
	{"UNIQUE", "FULLTEXT", "SPATIAL", "ALGORITHM = UNDEFINED", "ALGORITHM = MERGE",
		"ALGORITHM = TEMPTABLE"},
	{"DATABASE", "SCHEMA", "EVENT", "FUNCTION", "INDEX", "LOGFILE GROUP",
		"PROCEDURE", "SERVER", "SPATIAL REFERENCE SYSTEM", "TABLE", "TABLESPACE",
		"TRIGGER", "VIEW"},
	{"IF NOT EXISTS"},
	{"CUSTOM_FUZZ_STRING"},
}

var dropTokens = [][]string{
	{"TEMPORARY", "UNDO"},
	{"DATABASE", "SCHEMA", "EVENT", "INDEX", "LOGFILE GROUP",
		"PROCEDURE", "FUNCTION", "SERVER", "SPATIAL REFERENCE SYSTEM",
		"TABLE", "TABLESPACE", "TRIGGER", "VIEW"},
	{"IF EXISTS"},
	{"CUSTOM_FUZZ_STRING"},
	{"ON", "ENGINE = ", "RESTRICT", "CASCADE"},
}

var renameTokens = [][]string{
	{"TABLE"},
	{"CUSTOM_FUZZ_STRING"},
	{"TO"},
	{"CUSTOM_FUZZ_STRING"},
}

var truncateTokens = [][]string{
	{"TABLE"},
	{"CUSTOM_FUZZ_STRING"},
}

var setTokens = [][]string{
	{"CHARACTER SET", "CHARSET", "CUSTOM_FUZZ_STRING", "NAMES"},
	{"CUSTOM_FUZZ_STRING", "DEFAULT", "="},
	{"CUSTOM_FUZZ_STRING"},
}

var alterTokens = [][]string{
	{"DATABASE", "SCHEMA", "DEFINER = ", "EVENT", "FUNCTION", "INSTANCE",
		"LOGFILE GROUP", "PROCEDURE", "SERVER"},
	{"CUSTOM_FUZZ_STRING"},
	{"ON SCHEDULE", "ON COMPLETION PRESERVE", "ON COMPLETION NOT PRESERVE",
		"ADD UNDOFILE", "OPTIONS"},
	{"RENAME TO", "INITIAL_SIZE = "},
	{"ENABLE", "DISABLE", "DISABLE ON SLAVE", "ENGINE"},
	{"COMMENT"},
	{"DO"},
}

var alterTableTokens = [][]string{
	{"CUSTOM_FUZZ_STRING"},
	{"CUSTOM_ALTER_TABLE_OPTIONS"},
	{"PARTITION_OPTIONS_FOR_ALTER_TABLE"},
}

// Vitess-specific SHOW statement tokens.
var showTokens = [][]string{
	{"FULL", "EXTENDED", "GLOBAL", "SESSION"},
	{"TABLES", "DATABASES", "COLUMNS", "INDEX", "STATUS", "VARIABLES",
		"WARNINGS", "ERRORS", "PROCESSLIST", "GRANTS",
		"CREATE TABLE", "CREATE DATABASE",
		"VITESS_TABLETS", "VITESS_SHARDS", "VITESS_KEYSPACES",
		"VSCHEMA TABLES", "VSCHEMA VINDEXES"},
	{"FROM", "IN", "LIKE", "WHERE"},
	{"CUSTOM_FUZZ_STRING"},
}

// Transaction-control tokens.
var beginTokens = [][]string{
	{"WORK", ""},
}

var commitTokens = [][]string{
	{"WORK", "AND NO CHAIN", "AND CHAIN", "NO RELEASE", "RELEASE"},
}

var rollbackTokens = [][]string{
	{"WORK", "AND NO CHAIN", "AND CHAIN", "TO SAVEPOINT"},
	{"CUSTOM_FUZZ_STRING"},
}

// EXPLAIN/DESCRIBE tokens.
var explainTokens = [][]string{
	{"FORMAT = JSON", "FORMAT = TREE", "FORMAT = TRADITIONAL", "ANALYZE"},
	{"CUSTOM_FUZZ_STRING"},
}

// USE database tokens.
var useTokens = [][]string{
	{"CUSTOM_FUZZ_STRING"},
}

var alterTableOptions = []string{
	"ADD", "COLUMN", "FIRST", "AFTER", "INDEX", "KEY", "FULLTEXT", "SPATIAL",
	"CONSTRAINT", "UNIQUE", "FOREIGN KEY", "CHECK", "ENFORCED", "DROP", "ALTER",
	"NOT", "INPLACE", "COPY", "SET", "VISIBLE", "INVISIBLE", "DEFAULT", "CHANGE",
	"CHARACTER SET", "COLLATE", "DISABLE", "ENABLE", "KEYS", "TABLESPACE", "LOCK",
	"FORCE", "MODIFY", "SHARED", "EXCLUSIVE", "NONE", "ORDER BY", "RENAME COLUMN",
	"AS", "=", "ASC", "DESC", "WITH", "WITHOUT", "VALIDATION", "ADD PARTITION",
	"DROP PARTITION", "DISCARD PARTITION", "IMPORT PARTITION", "TRUNCATE PARTITION",
	"COALESCE PARTITION", "REORGANIZE PARTITION", "EXCHANGE PARTITION",
	"ANALYZE PARTITION", "CHECK PARTITION", "OPTIMIZE PARTITION", "REBUILD PARTITION",
	"REPAIR PARTITION", "REMOVE PARTITIONING", "USING", "BTREE", "HASH", "COMMENT",
	"KEY_BLOCK_SIZE", "WITH PARSER", "AUTOEXTEND_SIZE", "AUTO_INCREMENT", "AVG_ROW_LENGTH",
	"CHECKSUM", "INSERT_METHOD", "ROW_FORMAT", "DYNAMIC", "FIXED", "COMPRESSED",
	"REDUNDANT", "COMPACT", "SECONDARY_ENGINE_ATTRIBUTE", "STATS_AUTO_RECALC",
	"STATS_PERSISTENT", "STATS_SAMPLE_PAGES", "ZLIB", "LZ4", "ENGINE_ATTRIBUTE",
	"KEY_BLOCK_SIZE", "MAX_ROWS", "MIN_ROWS", "PACK_KEYS", "PASSWORD",
	"COMPRESSION", "CONNECTION", "DIRECTORY", "DELAY_KEY_WRITE", "ENCRYPTION",
	"STORAGE", "DISK", "MEMORY", "UNION",
}

// All statement types and their token arrays.
var stmtTypes = map[string][][]string{
	"DELETE":      deleteTokens,
	"INSERT":      insertTokens,
	"SELECT":      selectTokens,
	"UPDATE":      updateTokens,
	"LOAD":        loadTokens,
	"REPLACE":     replaceTokens,
	"CREATE":      createTokens,
	"DROP":        dropTokens,
	"RENAME":      renameTokens,
	"TRUNCATE":    truncateTokens,
	"SET":         setTokens,
	"ALTER":       alterTokens,
	"ALTER TABLE": alterTableTokens,
	"SHOW":        showTokens,
	"BEGIN":       beginTokens,
	"COMMIT":      commitTokens,
	"ROLLBACK":    rollbackTokens,
	"EXPLAIN":     explainTokens,
	"USE":         useTokens,
}

var stmtTypeEnum = map[int]string{
	0:  "DELETE",
	1:  "INSERT",
	2:  "SELECT",
	3:  "LOAD",
	4:  "REPLACE",
	5:  "CREATE",
	6:  "DROP",
	7:  "RENAME",
	8:  "TRUNCATE",
	9:  "SET",
	10: "ALTER",
	11: "ALTER TABLE",
	12: "SHOW",
	13: "BEGIN",
	14: "COMMIT",
	15: "ROLLBACK",
	16: "EXPLAIN",
	17: "USE",
	18: "SELECT", // Extra weight for SELECT (most common)
	19: "INSERT", // Extra weight for INSERT
}

// ---------------------------------------------------------------------------
// SQL generation helpers
// ---------------------------------------------------------------------------

func (f *ConsumeFuzzer) getKeyword() (string, error) {
	b, err := f.GetByte()
	if err != nil {
		return keywords[0], err
	}
	return keywords[int(b)%len(keywords)], nil
}

func (f *ConsumeFuzzer) chooseToken(tokens []string) (string, error) {
	b, err := f.GetByte()
	if err != nil {
		return "", err
	}
	token := tokens[int(b)%len(tokens)]
	if token == "CUSTOM_FUZZ_STRING" {
		return f.GetString()
	}
	if token == "CUSTOM_ALTER_TABLE_OPTIONS" {
		return f.createAlterTableOptions()
	}
	if token == "PARTITION_OPTIONS_FOR_ALTER_TABLE" {
		return f.createAlterTableOptions()
	}
	if containsString(needCustomString, token) {
		s, err := f.GetString()
		if err != nil {
			return token, nil
		}
		return token + " " + s, nil
	}
	return token, nil
}

func (f *ConsumeFuzzer) createAlterTableOptions() (string, error) {
	b, err := f.GetByte()
	if err != nil {
		return "", err
	}
	maxArgs := int(b)%30 + 1
	var sb strings.Builder
	for i := 0; i < maxArgs; i++ {
		tokenType, err := f.GetByte()
		if err != nil {
			break
		}
		if int(tokenType)%4 == 1 {
			s, err := f.GetString()
			if err != nil {
				break
			}
			sb.WriteString(" " + s)
		} else {
			idx, err := f.GetByte()
			if err != nil {
				break
			}
			sb.WriteString(" " + alterTableOptions[int(idx)%len(alterTableOptions)])
		}
	}
	return sb.String(), nil
}

func (f *ConsumeFuzzer) createAlterTableStmt() (string, error) {
	opts, err := f.createAlterTableOptions()
	if err != nil {
		return "", err
	}
	return "ALTER TABLE" + opts, nil
}

func (f *ConsumeFuzzer) createStmtArgs(tokenSlice [][]string) (string, error) {
	var query strings.Builder
	for _, tokens := range tokenSlice {
		include, err := f.GetBool()
		if err != nil {
			break
		}
		if !include {
			continue
		}
		if len(tokens) > 1 {
			chosen, err := f.chooseToken(tokens)
			if err != nil {
				break
			}
			query.WriteString(" " + chosen)
		} else {
			token := tokens[0]
			if token == "CUSTOM_FUZZ_STRING" {
				s, err := f.GetString()
				if err != nil {
					break
				}
				query.WriteString(" " + s)
				continue
			}
			if containsString(needCustomString, token) {
				s, err := f.GetString()
				if err != nil {
					break
				}
				token = fmt.Sprintf("%s %s", token, s)
			}
			query.WriteString(fmt.Sprintf(" %s", token))
		}
	}
	return query.String(), nil
}

func (f *ConsumeFuzzer) createStmt() (string, error) {
	b, err := f.GetByte()
	if err != nil {
		return "", err
	}
	stmtIndex := int(b) % len(stmtTypeEnum)
	queryType := stmtTypeEnum[stmtIndex]
	tokens := stmtTypes[queryType]

	if queryType == "ALTER TABLE" {
		return f.createAlterTableStmt()
	}

	var query strings.Builder
	query.WriteString(queryType)
	args, err := f.createStmtArgs(tokens)
	if err != nil {
		return query.String(), nil
	}
	query.WriteString(" " + args)
	return query.String(), nil
}

func (f *ConsumeFuzzer) createQuery() (string, error) {
	b, err := f.GetByte()
	if err != nil {
		return "", err
	}
	maxLen := int(b)%60 + 1
	var query strings.Builder
	for i := 0; i < maxLen; i++ {
		useKeyword, err := f.GetBool()
		if err != nil {
			break
		}
		if useKeyword {
			kw, err := f.getKeyword()
			if err != nil {
				break
			}
			query.WriteString(" " + kw)
		} else {
			s, err := f.GetString()
			if err != nil {
				break
			}
			query.WriteString(" " + s)
		}
	}
	result := query.String()
	if result == "" {
		return "", fmt.Errorf("could not create a query")
	}
	return result, nil
}

// GetSQLString generates a semi-structured SQL string suitable for
// parser fuzzing. It alternates between fully structured statements
// (SELECT, INSERT, ..., plus Vitess-specific SHOW / transaction control)
// and semi-random keyword combinations.
func (f *ConsumeFuzzer) GetSQLString() (string, error) {
	structured, err := f.GetBool()
	if err != nil {
		return "", err
	}
	if structured {
		return f.createStmt()
	}
	return f.createQuery()
}
