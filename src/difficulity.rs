use redb::{Database, ReadableDatabase, ReadableTable};

use crate::Block;
use crate::db::BLOCKS_TABLE;

const DIFFICULTY_WINDOW: usize = 10;
const TARGET_BLOCK_TIME: u64 = 600;
const TARGET_TIMESPAN: u64 = TARGET_BLOCK_TIME * DIFFICULTY_WINDOW as u64;

pub fn last_window_timespan(db: &Database) -> Result<u64, Box<dyn std::error::Error>> {
    let read_txn = db.begin_read()?;
    let table = read_txn.open_table(BLOCKS_TABLE)?;

    let mut blocks = Vec::with_capacity(DIFFICULTY_WINDOW);
    for entry in table.range(0u64..)?.rev().take(DIFFICULTY_WINDOW) {
        let (_height, value) = entry?;
        let block: Block = wincode::deserialize(value.value())?;
        blocks.push(block);
    }
    blocks.reverse();

    let first = blocks.first().ok_or("not enough blocks")?;
    let last = blocks.last().ok_or("not enough blocks")?;

    let span = last
        .block_header
        .timestamp
        .duration_since(first.block_header.timestamp)
        .unwrap_or_default()
        .as_secs();

    Ok(span)
}

pub fn calculate_next_difficulty(
    db: &Database,
    current_height: u64,
) -> Result<u32, Box<dyn std::error::Error>> {
    if current_height < DIFFICULTY_WINDOW as u64 {
        return Ok(2);
    }

    let timespan = last_window_timespan(db)?.max(1);

    let next = (2u128 * TARGET_TIMESPAN as u128 / timespan as u128) as u32;
    Ok(next.clamp(1, 6))
}
