## CVE-2017-15286

credit by SmallC@HaoTeam

### ASAN output

$ sqlite3 PoC.db ".dump"

```
BEGIN TRANSACTION;
/****** CORRUPTION ERROR *******/
/****** database disk image is malformed ******/
CREATE TABLE IF NOT EXISTS "events_entry" (
    "id" integer NOT NULL PRIMARY KEY,
    "title" varchar(128) NOT NULL,
    "start" datetime NOT NULL,
    "place" varchar(255) NOT NULL,
    "location" varchar(255) NOT NULL
);
ASAN:SIGSEGV
=================================================================
==11908==ERROR: AddressSanitizer: SEGV on unknown address 0x00000000 (pc 0x0808fb69 bp 0x00000004 sp 0xffc64550 T0)
    #0 0x808fb68 in tableColumnList /home/user/Desktop/fuzz/sqlite/ta/src/shell.c:3804
    #1 0x808fb68 in dump_callback /home/user/Desktop/fuzz/sqlite/ta/src/shell.c:3922
    #2 0x8482d97 in sqlite3_exec /home/user/Desktop/fuzz/sqlite/ta/sqlite3.c:112207
    #3 0x804a6b3 in run_schema_dump_query /home/user/Desktop/fuzz/sqlite/ta/src/shell.c:4009
    #4 0x8096e3c in do_meta_command /home/user/Desktop/fuzz/sqlite/ta/src/shell.c:5694
    #5 0x805e40c in main /home/user/Desktop/fuzz/sqlite/ta/src/shell.c:8308
    #6 0xf6fce636 in __libc_start_main (/lib/i386-linux-gnu/libc.so.6+0x18636)
    #7 0x805ff3e  (/home/default/Desktop/sqlite3fuzz/ta/sqlite3+0x805ff3e)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV /home/user/Desktop/fuzz/sqlite/ta/src/shell.c:3804 tableColumnList
==11908==ABORTING
```

### bug introduction

A null pointer reference happens in sqlite/shell.c:3766. Though Windows and Linux prevent the potential risks of null pointer reference, still might be exploitable in macOS.

### root cause

The bug dues to the ignorance of potential cases when `sqlite3_step(pStmt)==SQLITE_ROW` is false. And through PoC.db the value is 0x65.

``` C
static char **tableColumnList(ShellState *p, const char *zTab){
  // 1
  //
  //azCol initialized here. 
  char **azCol = 0;      
  
  sqlite3_stmt *pStmt;
  char *zSql;
  int nCol = 0;
  int nAlloc = 0;
  int nPK = 0;       /* Number of PRIMARY KEY columns seen */
  int isIPK = 0;     /* True if one PRIMARY KEY column of type INTEGER */
  int preserveRowid = ShellHasFlag(p, SHFLG_PreserveRowid);
  int rc;
  zSql = sqlite3_mprintf("PRAGMA table_info=%Q", zTab);
  rc = sqlite3_prepare_v2(p->db, zSql, -1, &pStmt, 0);
  sqlite3_free(zSql);
  if( rc ) return 0;
  
  // 2
  //
  // while loop could be not executed
  while( sqlite3_step(pStmt)==SQLITE_ROW ){
  
    if( nCol>=nAlloc-2 ){
      nAlloc = nAlloc*2 + nCol + 10;
      azCol = sqlite3_realloc(azCol, nAlloc*sizeof(azCol[0]));
      if( azCol==0 ){
        raw_printf(stderr, "Error: out of memory\n");
        exit(1);
      }
    }
    azCol[++nCol] = sqlite3_mprintf("%s", sqlite3_column_text(pStmt, 1));
    if( sqlite3_column_int(pStmt, 5) ){
      nPK++;
      if( nPK==1
       && sqlite3_stricmp((const char*)sqlite3_column_text(pStmt,2),
                          "INTEGER")==0
      ){
        isIPK = 1;
      }else{
        isIPK = 0;
      }
    }
  }

  sqlite3_finalize(pStmt);
  
  // 3
  //
  // Referencing azCol result in null pointer reference because azCol could still be zero.
  azCol[0] = 0;
  azCol[nCol+1] = 0;
  ...
}
```
