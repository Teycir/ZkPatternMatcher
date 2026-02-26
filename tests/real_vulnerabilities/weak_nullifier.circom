pragma circom 2.0.0;

// VULNERABILITY: Weak nullifier without uniqueness constraint
// Source: zkBugs - StealthDrop, Tornado Cash variants
// Impact: Double-spend attacks, replay attacks
// CVE: Similar to CVE-2024-XXXXX patterns

template WeakNullifier() {
    signal input secret;
    signal input publicKey;
    signal output nullifier;
    
    // BUG: Nullifier derived from non-unique inputs
    // No constraint ensuring nullifier uniqueness per action
    nullifier <-- secret + publicKey;
    
    // MISSING: 
    // 1. Hash-based nullifier: nullifier === hash(secret, nonce, action_id)
    // 2. Uniqueness tracking in smart contract
    // 3. Binding to specific action/epoch
    
    // Current implementation allows:
    // - Replay attacks with same secret
    // - Double-spend if nullifier not tracked
}

component main = WeakNullifier();
