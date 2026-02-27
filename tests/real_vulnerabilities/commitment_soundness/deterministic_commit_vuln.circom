pragma circom 2.0.0;

// VULNERABLE: commitment uses single-input Poseidon (no randomness)
template DeterministicCommit() {
    signal input value;
    signal output commitment;

    // FIRES: deterministic_commitment + commitment_not_exposed (no public constraint)
    // Using placeholder - real circuit would use: component hasher = Poseidon(1);
    commitment <== value;  // Simplified for testing
}

component main { public [value] } = DeterministicCommit();
