mod db;
mod difficulity;
mod mining;

use std::time::{Duration, SystemTime};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hex;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use wincode::{SchemaRead, SchemaWrite};

#[derive(SchemaWrite, SchemaRead)]
struct Transaction {
    sender: String,
    receiver: String,
    amount: u64,
    fee: u64,
    nonce: u64,
    signature: Vec<u8>,
}

type TxId = [u8; 32];

impl Transaction {
    pub fn compute_txid(&self) -> TxId {
        let tx_data = (
            &self.sender,
            &self.receiver,
            self.amount,
            self.fee,
            self.nonce,
        );

        let encode = wincode::serialize(&tx_data).expect("Failed to serialize tx data");

        Sha256::digest(&encode).into()
    }
    fn signing_payload(&self) -> Vec<u8> {
        wincode::serialize(&(
            &self.sender,
            &self.receiver,
            self.amount,
            self.fee,
            self.nonce,
        ))
        .expect("serialize")
    }

    pub fn verify_signature(&self) -> bool {
        let Ok(pk) = hex::decode(&self.sender) else {
            return false;
        };
        let Ok(pk) = <[u8; 32]>::try_from(pk.as_slice()) else {
            return false;
        };
        let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
            return false;
        };
        let Ok(sig) = Signature::from_slice(&self.signature) else {
            return false;
        };
        vk.verify(&self.signing_payload(), &sig).is_ok()
    }
}

#[derive(SchemaWrite, SchemaRead)]
pub(crate) struct BlockHeader {
    timestamp: SystemTime,
    prev_hash: String,
    block_height: u64,
    nonce: u64,
    merkle_root: String,
}

#[derive(SchemaWrite, SchemaRead)]
pub(crate) struct Block {
    block_header: BlockHeader,
    data: Vec<Transaction>,
}

#[derive(SchemaWrite, SchemaRead)]
enum Message {
    Handshake { version: u32 },
    GetBlock { block_height: u32 },
    NewTransaction(Transaction),
    NewBlock(Block),
}

const TRANSACTIONS: TableDefinition<TxId, &[u8]> = TableDefinition::new("transactions");

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(8001);
    let listener = TcpListener::bind(format!("127.0.0.1:{port}")).await?;
    let (tx, _) = broadcast::channel(128);

    let mut peers: Vec<SocketAddr> = Vec::new();

    let seed: String = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "127.0.0.1:8000".to_string());
    let seed_addr: SocketAddr = seed.parse()?;
    let self_addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;

    let outbound_socket = if seed_addr == self_addr {
        println!("Skipping self-connect to {}", seed_addr);
        None
    } else {
        match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(seed_addr)).await {
            Ok(Ok(socket)) => Some(socket),
            Ok(Err(e)) => {
                eprintln!("Could not connect to seed {}: {}", seed_addr, e);
                None
            }
            Err(_) => {
                eprintln!("Timed out connecting to seed {}", seed_addr);
                None
            }
        }
    };

    let db = std::sync::Arc::new(crate::db::initialize_db(&format!("mempool-{port}.redb"))?);

    let chain_tip = std::sync::Arc::new(AtomicU64::new(
        db::latest_block(&db)?
            .map(|(height, _)| height)
            .unwrap_or(u64::MAX),
    ));

    if let Some(outbound_socket) = outbound_socket {
        spawn_peer(
            tx.clone(),
            outbound_socket,
            db.clone(),
            chain_tip.clone(),
            seed_addr,
        );
    }
    {
        let wtx = db.begin_write()?;
        wtx.open_table(TRANSACTIONS)?;
        wtx.commit()?;
    }
    {
        let db = db.clone();
        let block_tx = tx.clone();
        let chain_tip = chain_tip.clone();
        tokio::task::spawn_blocking(move || mining::mine(db, block_tx, chain_tip));
    }

    loop {
        let (mut socket, peer_addr) = listener.accept().await?;
        println!("✅ New peer connected: {}", peer_addr);
        peers.push(peer_addr);

        let db = db.clone();
        let chain_tip = chain_tip.clone();
        spawn_peer(tx.clone(), socket, db, chain_tip, peer_addr);
    }
}

fn spawn_peer(
    tx: tokio::sync::broadcast::Sender<std::sync::Arc<[u8]>>,
    socket: tokio::net::TcpStream,
    db: std::sync::Arc<redb::Database>,
    chain_tip: std::sync::Arc<std::sync::atomic::AtomicU64>,
    peer_addr: std::net::SocketAddr,
) {
    let mut rx = tx.subscribe();
    let gossip_tx = tx.clone();
    let (mut reader, mut writer) = socket.into_split();

    let writer_task = tokio::spawn(async move {
        while let Ok(bytes) = rx.recv().await {
            if writer.write_all(&bytes).await.is_err() {
                break;
            }
        }
    });

    tokio::spawn(async move {
        let mut header = [0u8; 4];

        loop {
            if let Err(e) = reader.read_exact(&mut header).await {
                println!("🔌 Peer {} disconnected: {}", peer_addr, e);
                break;
            }

            let len = u32::from_be_bytes(header) as usize;
            if len == 0 || len > 8 * 1024 * 1024 {
                eprintln!("❌ Peer {} sent invalid frame length {}", peer_addr, len);
                break;
            }

            let mut buf = vec![0u8; len];
            if let Err(e) = reader.read_exact(&mut buf).await {
                eprintln!("❌ Peer {} sent truncated frame: {}", peer_addr, e);
                break;
            }

            let msg: Message = match wincode::deserialize(&buf) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("❌ Peer {} sent malformed message: {}", peer_addr, e);
                    break;
                }
            };

            match msg {
                Message::NewBlock(msg) => {
                    let block_height = msg.block_header.block_height;

                    match mining::verify_and_store_block(&db, msg) {
                        Ok(true) => {
                            chain_tip.store(block_height, Ordering::SeqCst);
                            println!("✅ Stored block {} from peer {}", block_height, peer_addr);
                            let mut framed = Vec::with_capacity(4 + buf.len());
                            framed.extend_from_slice(&header);
                            framed.extend_from_slice(&buf);
                            let _ = gossip_tx.send(std::sync::Arc::from(framed));
                        }
                        Ok(false) => {
                            println!("❌ Peer {} sent an invalid or stale block", peer_addr);
                        }
                        Err(e) => {
                            eprintln!("❌ Failed to store block from peer {}: {}", peer_addr, e);
                        }
                    }
                }
                Message::Handshake { version: _ } => {}
                Message::NewTransaction(msg) => {
                    if msg.amount == 0 {
                        println!("Amount must be greater than zero");
                        continue;
                    }

                    if msg.sender == msg.receiver {
                        println!("sender and receiver are the same");
                        continue;
                    }

                    if msg.fee <= 2 {
                        println!("fee must be above 2");
                        continue;
                    }

                    if !msg.verify_signature() {
                        println!("tampered data or signature not right");
                        continue;
                    }

                    let txid: TxId = msg.compute_txid();

                    let already_exists = {
                        let read_tx = match db.begin_read() {
                            Ok(tx) => tx,
                            Err(e) => {
                                eprintln!("❌ Failed to begin read: {}", e);
                                continue;
                            }
                        };

                        let table = match read_tx.open_table(TRANSACTIONS) {
                            Ok(t) => t,
                            Err(e) => {
                                eprintln!("open_table: {}", e);
                                continue;
                            }
                        };

                        match table.get(txid) {
                            Ok(v) => v.is_some(),
                            Err(e) => {
                                eprintln!("get: {}", e);
                                continue;
                            }
                        }
                    };

                    if already_exists {
                        println!("transaction found in mempool, no need to add it again");
                        continue;
                    }

                    let bytes = match wincode::serialize(&msg) {
                        Ok(b) => b,
                        Err(e) => {
                            eprintln!("serialize: {}", e);
                            continue;
                        }
                    };

                    let write_tx = match db.begin_write() {
                        Ok(tx) => tx,
                        Err(e) => {
                            eprintln!("begin_write: {}", e);
                            continue;
                        }
                    };

                    {
                        let mut table = match write_tx.open_table(TRANSACTIONS) {
                            Ok(t) => t,
                            Err(e) => {
                                eprintln!("open_table: {}", e);
                                continue;
                            }
                        };

                        if let Err(e) = table.insert(txid, bytes.as_slice()) {
                            eprintln!("insert: {}", e);
                            continue;
                        }
                    }

                    if let Err(e) = write_tx.commit() {
                        eprintln!("commit: {}", e);
                        continue;
                    }

                    println!("💾 Saved transaction {:?}", txid);
                    let mut framed = Vec::with_capacity(4 + buf.len());
                    framed.extend_from_slice(&header);
                    framed.extend_from_slice(&buf);
                    let _ = gossip_tx.send(std::sync::Arc::from(framed));
                }

                Message::GetBlock { block_height: _ } => {}
            }

            println!("📦 Received {} bytes from {}", buf.len(), peer_addr);
        }
        writer_task.abort();
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signed_transaction(signing_key: &SigningKey, nonce: u64) -> Transaction {
        let mut tx = Transaction {
            sender: hex::encode(signing_key.verifying_key().to_bytes()),
            receiver: hex::encode([2u8; 32]),
            amount: 10,
            fee: 3,
            nonce,
            signature: Vec::new(),
        };
        tx.signature = signing_key.sign(&tx.signing_payload()).to_bytes().to_vec();
        tx
    }

    fn merkle_root(txs: &[Transaction]) -> String {
        let mut level: Vec<[u8; 32]> = txs.iter().map(|tx| tx.compute_txid()).collect();
        while level.len() > 1 {
            if level.len() % 2 == 1 {
                level.push(*level.last().unwrap());
            }
            level = level
                .chunks(2)
                .map(|pair| {
                    let mut h = Sha256::new();
                    h.update(pair[0]);
                    h.update(pair[1]);
                    h.finalize().into()
                })
                .collect();
        }
        hex::encode(level[0])
    }

    fn header_hash(block: &Block) -> String {
        hex::encode(Sha256::digest(
            wincode::serialize(&block.block_header).unwrap(),
        ))
    }

    fn mine_into(db: &Database, prev_hash: String, height: u64, txs: Vec<Transaction>) -> Block {
        let difficulty = difficulity::calculate_next_difficulty(db, height + 1).unwrap_or(2);
        let mut block = Block {
            block_header: BlockHeader {
                timestamp: SystemTime::now(),
                prev_hash,
                block_height: height,
                nonce: 0,
                merkle_root: merkle_root(&txs),
            },
            data: txs,
        };
        while header_hash(&block)
            .chars()
            .take_while(|c| *c == '0')
            .count()
            < difficulty as usize
        {
            block.block_header.nonce += 1;
        }
        block
    }

    #[test]
    fn verifies_and_stores_a_peer_block() {
        let path = std::env::temp_dir().join(format!("peep-mining-{}.redb", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let db = db::initialize_db(path.to_str().unwrap()).unwrap();

        let key = SigningKey::from_bytes(&[7u8; 32]);
        let tx = signed_transaction(&key, 0);

        {
            let wtx = db.begin_write().unwrap();
            {
                let mut table = wtx.open_table(TRANSACTIONS).unwrap();
                let bytes = wincode::serialize(&tx).unwrap();
                table.insert(tx.compute_txid(), bytes.as_slice()).unwrap();
            }
            wtx.commit().unwrap();
        }

        let genesis = mine_into(&db, hex::encode([0u8; 32]), 0, vec![tx]);
        assert!(mining::verify_and_store_block(&db, genesis).unwrap());

        let (height, bytes) = db::latest_block(&db).unwrap().unwrap();
        assert_eq!(height, 0);
        let stored: Block = wincode::deserialize(&bytes).unwrap();
        assert_eq!(stored.block_header.block_height, 0);

        let read = db.begin_read().unwrap();
        let pool = read.open_table(TRANSACTIONS).unwrap();
        assert!(pool.iter().unwrap().next().is_none());

        let tx2 = signed_transaction(&key, 1);
        let prev_hash = header_hash(&stored);
        let block1 = mine_into(&db, prev_hash.clone(), 1, vec![tx2]);
        assert!(mining::verify_and_store_block(&db, block1).unwrap());

        let stale = mine_into(&db, prev_hash, 1, vec![signed_transaction(&key, 2)]);
        assert!(!mining::verify_and_store_block(&db, stale).unwrap());

        drop(db);
        let _ = std::fs::remove_file(&path);
    }
}
