use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

pub const BLOCKS_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("blocks");

pub const ACCOUNTS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("accounts");

pub fn latest_block(db: &Database) -> Result<Option<(u64, Vec<u8>)>, Box<dyn std::error::Error>> {
    let read_txn = db.begin_read()?;
    let table = read_txn.open_table(BLOCKS_TABLE)?;

    match table.last()? {
        Some((height, value)) => Ok(Some((height.value(), value.value().to_vec()))),
        None => Ok(None),
    }
}

pub fn initialize_db(path: &str) -> Result<Database, Box<dyn std::error::Error>> {
    let db = Database::create(path)?;

    let write_txn = db.begin_write()?;
    {
        write_txn.open_table(BLOCKS_TABLE)?;
        write_txn.open_table(ACCOUNTS_TABLE)?;
    }
    write_txn.commit()?;

    Ok(db)
}
