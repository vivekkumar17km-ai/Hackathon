"""
SourceMark Tamper-Evident Audit Ledger
Calculates cryptographic hash chaining and performs server-side chain validation.

Ledger Limitations Notice:
A hash-linked ledger guarantees tamper-evidence against uncoordinated modifications:
any altered block payload or broken link causes subsequent recalculations to fail.
However, because this ledger runs on a local database node, an administrator with raw
database write access could theoretically rewrite the entire table and recalculate
all hashes. For absolute non-repudiation, periodic ledger root hashes should be
anchored to an external append-only log or distributed notary.
"""

import hashlib
from typing import Dict, Any, List, Optional, Tuple
from .crypto_utils import canonical_json, compute_sha256

GENESIS_PREV_HASH = "0" * 64
LIMITATIONS_NOTICE = (
    "A hash-linked ledger guarantees tamper-evidence against retroactive bitstream alterations: "
    "any modification to block headers, sequence numbers, or payload fields invalidates the cryptographic hash chain. "
    "Note: A local database administrator with full write privileges could theoretically reconstruct an entire chain. "
    "True immutability requires external multi-party anchoring or hardware append-only storage."
)


def compute_block_hash(
    block_id: str,
    block_number: int,
    block_type: str,
    prev_hash: str,
    timestamp: str,
    payload: Dict[str, Any]
) -> str:
    """
    Calculate deterministic SHA-256 block hash over canonical payload representation.
    """
    canonical_payload_str = canonical_json(payload)
    raw_block_data = f"{block_id}|{block_number}|{block_type}|{prev_hash}|{timestamp}|{canonical_payload_str}"
    return compute_sha256(raw_block_data.encode("utf-8"))


def validate_chain(blocks: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Perform rigorous, comprehensive cryptographic validation of an audit ledger block sequence.
    
    Validates:
    1. Non-empty block list
    2. Genesis block specification (blockNumber 1, zero previous hash, valid recalculation)
    3. Strict sequential ordering (blockNumber = prev + 1)
    4. Exact parent-child hash linkage (block.prevHash == prev_block.currentHash)
    5. Exact payload and header integrity via recomputed SHA-256 hash
    """
    import datetime

    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    if not blocks:
        return {
            "isValid": False,
            "totalBlocks": 0,
            "brokenAtBlock": None,
            "details": [{"error": "Ledger is empty: no genesis block found"}],
            "limitationsNotice": LIMITATIONS_NOTICE,
            "timestamp": now_iso
        }

    # Step 1: Validate Genesis block
    genesis = blocks[0]
    genesis_id = genesis.get("id") or "BLK-0001"
    genesis_num = genesis.get("blockNumber")
    genesis_prev = genesis.get("prevHash")
    genesis_curr = genesis.get("currentHash")
    genesis_type = genesis.get("type")
    genesis_time = genesis.get("timestamp")
    genesis_payload = genesis.get("payload", {})

    if genesis_num != 1:
        return {
            "isValid": False,
            "totalBlocks": len(blocks),
            "brokenAtBlock": genesis_id,
            "details": [{
                "blockId": genesis_id,
                "blockNumber": genesis_num,
                "error": f"Genesis block must have blockNumber 1, found {genesis_num}"
            }],
            "limitationsNotice": LIMITATIONS_NOTICE,
            "timestamp": now_iso
        }

    if genesis_prev != GENESIS_PREV_HASH:
        return {
            "isValid": False,
            "totalBlocks": len(blocks),
            "brokenAtBlock": genesis_id,
            "details": [{
                "blockId": genesis_id,
                "blockNumber": genesis_num,
                "error": f"Genesis block must have 64 zeros as prevHash, found {genesis_prev}"
            }],
            "limitationsNotice": LIMITATIONS_NOTICE,
            "timestamp": now_iso
        }

    expected_genesis_hash = compute_block_hash(
        genesis_id, genesis_num, genesis_type, genesis_prev, genesis_time, genesis_payload
    )
    if genesis_curr != expected_genesis_hash:
        return {
            "isValid": False,
            "totalBlocks": len(blocks),
            "brokenAtBlock": genesis_id,
            "details": [{
                "blockId": genesis_id,
                "blockNumber": genesis_num,
                "error": "Genesis block data altered: recalculated hash does not match currentHash",
                "recordedHash": genesis_curr,
                "recalculatedHash": expected_genesis_hash
            }],
            "limitationsNotice": LIMITATIONS_NOTICE,
            "timestamp": now_iso
        }

    # Step 2: Validate subsequent blocks
    for i in range(1, len(blocks)):
        prev = blocks[i - 1]
        curr = blocks[i]
        curr_id = curr.get("id") or f"BLK-{i+1:04d}"
        curr_num = curr.get("blockNumber")
        curr_prev = curr.get("prevHash")
        curr_curr = curr.get("currentHash")
        curr_type = curr.get("type")
        curr_time = curr.get("timestamp")
        curr_payload = curr.get("payload", {})

        # Sequential block number
        expected_num = prev.get("blockNumber", i) + 1
        if curr_num != expected_num:
            return {
                "isValid": False,
                "totalBlocks": len(blocks),
                "brokenAtBlock": curr_id,
                "details": [{
                    "blockId": curr_id,
                    "blockNumber": curr_num,
                    "error": f"Non-sequential block number: expected {expected_num}, found {curr_num}"
                }],
                "limitationsNotice": LIMITATIONS_NOTICE,
                "timestamp": now_iso
            }

        # Hash linkage check
        if curr_prev != prev.get("currentHash"):
            return {
                "isValid": False,
                "totalBlocks": len(blocks),
                "brokenAtBlock": curr_id,
                "details": [{
                    "blockId": curr_id,
                    "blockNumber": curr_num,
                    "error": f"Broken link: prevHash does not match parent Block #{prev.get('blockNumber')} hash",
                    "expectedPrevHash": prev.get("currentHash"),
                    "recordedPrevHash": curr_prev
                }],
                "limitationsNotice": LIMITATIONS_NOTICE,
                "timestamp": now_iso
            }

        # Recomputed hash check
        expected_curr_hash = compute_block_hash(
            curr_id, curr_num, curr_type, curr_prev, curr_time, curr_payload
        )
        if curr_curr != expected_curr_hash:
            return {
                "isValid": False,
                "totalBlocks": len(blocks),
                "brokenAtBlock": curr_id,
                "details": [{
                    "blockId": curr_id,
                    "blockNumber": curr_num,
                    "error": "Block data or payload has been modified: computed hash mismatch",
                    "recordedHash": curr_curr,
                    "recalculatedHash": expected_curr_hash
                }],
                "limitationsNotice": LIMITATIONS_NOTICE,
                "timestamp": now_iso
            }

    return {
        "isValid": True,
        "totalBlocks": len(blocks),
        "brokenAtBlock": None,
        "details": [],
        "limitationsNotice": LIMITATIONS_NOTICE,
        "timestamp": now_iso
    }

