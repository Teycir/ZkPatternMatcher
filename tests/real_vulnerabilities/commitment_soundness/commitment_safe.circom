pragma circom 2.0.0;

// SAFE: hiding commitment with randomness, constrained output
template SafeCommit() {
    signal input value;
    signal input randomness;
    signal output commitment;

    // Using placeholder - real circuit would use: component hasher = Poseidon(2);
    commitment <== value + randomness;  // Simplified for testing
    // No deterministic_commitment or nullifier_without_secret should fire
}

component main { public [commitment] } = SafeCommit();
