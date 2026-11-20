use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, SystemTime};

use redb::{Database, ReadableDatabase, ReadableTable, WriteTransaction};
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;

use crate::db::{BLOCKS_TABLE, latest_block};
use crate::difficulity::calculate_next_difficulty;
use crate::{Block, BlockHeader, Message, TRANSACTIONS, Transaction};

const MAX_BLOCK_TRANSACTIONS: usize = 100;
const MEMPOOL_POLL_INTERVAL: Duration = Duration::from_secs(1);

fn import_mempool_transactions(db: &Database) -> Result<Vec<Transaction>, Box<dyn Error>> {
    let read_txn = db.begin_read()?;
    let table = read_txn.open_table(TRANSACTIONS)?;

    let mut transactions = Vec::new();

    for entry in table.iter()? {
        let (_txid, value) = entry?;
        let tx: Transaction = wincode::deserialize(value.value())?;
        transactions.push(tx);
    }

    Ok(transactions)
}

fn calculate_block_hash(block: &Block) -> String {
    let serialized_header =
        wincode::serialize(&block.block_header).expect("failed to serialize block header");
    hex::encode(Sha256::digest(&serialized_header))
}

fn count_leading_zeros(hash: &str) -> u32 {
    hash.chars().take_while(|c| *c == '0').count() as u32
}

fn calculate_merkle_root(transactions: &[Transaction]) -> String {
    if transactions.is_empty() {
        return hex::encode([0u8; 32]);
    }

    let mut level: Vec<[u8; 32]> = transactions.iter().map(|tx| tx.compute_txid()).collect();

    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().unwrap());
        }

        level = level
            .chunks(2)
            .map(|pair| {
                let mut hasher = Sha256::new();
                hasher.update(pair[0]);
                hasher.update(pair[1]);
                hasher.finalize().into()
            })
            .collect()
    }

    hex::encode(level[0])
}

fn frame(msg: &Message) -> Vec<u8> {
    let body = wincode::serialize(msg).expect("serialize");
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

fn difficulty_for(db: &Database, block_height: u64) -> u32 {
    calculate_next_difficulty(db, block_height + 1).unwrap_or(2)
}

fn store_block(write_txn: &WriteTransaction, block: &Block) -> Result<bool, Box<dyn Error>> {
    let mut table = write_txn.open_table(BLOCKS_TABLE)?;

    let (expected_prev_hash, expected_height) = match table.last()? {
        Some((height, value)) => {
            let prev_block: Block = wincode::deserialize(value.value())?;
            (calculate_block_hash(&prev_block), height.value() + 1)
        }
        None => (hex::encode([0u8; 32]), 0),
    };

    if block.block_header.block_height != expected_height
        || block.block_header.prev_hash != expected_prev_hash
    {
        return Ok(false);
    }

    let block_bytes = wincode::serialize(block)?;
    table.insert(block.block_header.block_height, block_bytes.as_slice())?;

    let mut pool = write_txn.open_table(TRANSACTIONS)?;
    for transaction in &block.data {
        pool.remove(transaction.compute_txid())?;
    }

    Ok(true)
}

pub fn mine(db: Arc<Database>, block_tx: broadcast::Sender<Arc<[u8]>>, chain_tip: Arc<AtomicU64>) {
    'outer: loop {
        let mut transactions = match import_mempool_transactions(&db) {
            Ok(transactions) => transactions,
            Err(e) => {
                eprintln!("❌ Failed to read mempool: {}", e);
                thread::sleep(MEMPOOL_POLL_INTERVAL);
                continue;
            }
        };

        if transactions.is_empty() {
            thread::sleep(MEMPOOL_POLL_INTERVAL);
            continue;
        }

        transactions.sort_by(|a, b| b.fee.cmp(&a.fee));
        transactions.truncate(MAX_BLOCK_TRANSACTIONS);

        let merkle_root = calculate_merkle_root(&transactions);

        let (prev_hash, block_height) = match latest_block(&db) {
            Ok(Some((height, bytes))) => match wincode::deserialize::<Block>(&bytes) {
                Ok(prev_block) => (calculate_block_hash(&prev_block), height + 1),
                Err(e) => {
                    eprintln!("❌ Failed to deserialize previous block: {}", e);
                    thread::sleep(MEMPOOL_POLL_INTERVAL);
                    continue;
                }
            },
            Ok(None) => (hex::encode([0u8; 32]), 0),
            Err(e) => {
                eprintln!("❌ Failed to read chain tip: {}", e);
                thread::sleep(MEMPOOL_POLL_INTERVAL);
                continue;
            }
        };

        let difficulty = difficulty_for(&db, block_height);
        let tip_snapshot = chain_tip.load(Ordering::SeqCst);

        let mut block: Block = Block {
            block_header: BlockHeader {
                timestamp: SystemTime::now(),
                prev_hash,
                block_height,
                nonce: 0,
                merkle_root,
            },
            data: transactions,
        };

        let mut nonce = 0u64;

        loop {
            if chain_tip.load(Ordering::SeqCst) != tip_snapshot {
                continue 'outer;
            }

            block.block_header.nonce = nonce;
            let calculated_hash = calculate_block_hash(&block);

            if count_leading_zeros(&calculated_hash) < difficulty {
                nonce += 1;
                continue;
            }

            let write_txn = match db.begin_write() {
                Ok(write_txn) => write_txn,
                Err(e) => {
                    eprintln!("❌ Failed to begin write transaction: {}", e);
                    thread::sleep(MEMPOOL_POLL_INTERVAL);
                    continue 'outer;
                }
            };

            match store_block(&write_txn, &block) {
                Ok(true) => {}
                Ok(false) => continue 'outer,
                Err(e) => {
                    eprintln!("❌ Failed to store mined block: {}", e);
                    thread::sleep(MEMPOOL_POLL_INTERVAL);
                    continue 'outer;
                }
            }

            if let Err(e) = write_txn.commit() {
                eprintln!("❌ Failed to commit mined block: {}", e);
                continue 'outer;
            }

            println!(
                "✅ mined block {}: {} (nonce {})",
                block_height, calculated_hash, nonce
            );

            let bytes = Arc::from(frame(&Message::NewBlock(block)));
            let _ = block_tx.send(bytes);

            break;
        }
    }
}

pub fn verify_and_store_block(db: &Database, block: Block) -> Result<bool, Box<dyn Error>> {
    if block.data.len() > MAX_BLOCK_TRANSACTIONS {
        return Ok(false);
    }

    if calculate_merkle_root(&block.data) != block.block_header.merkle_root {
        return Ok(false);
    }

    if !block.data.iter().all(|transaction| {
        transaction.amount > 0
            && transaction.sender != transaction.receiver
            && transaction.verify_signature()
    }) {
        return Ok(false);
    }

    let difficulty = difficulty_for(db, block.block_header.block_height);
    let block_hash = calculate_block_hash(&block);

    if count_leading_zeros(&block_hash) < difficulty {
        return Ok(false);
    }

    let write_txn = db.begin_write()?;

    if !store_block(&write_txn, &block)? {
        return Ok(false);
    }

    write_txn.commit()?;

    Ok(true)
}
