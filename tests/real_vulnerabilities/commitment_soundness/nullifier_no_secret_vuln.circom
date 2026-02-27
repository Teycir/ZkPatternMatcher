pragma circom 2.0.0;

// VULNERABLE: nullifier derived from single public signal
template WeakNullifier() {
    signal input externalNullifier;
    signal output nullifier;

    // FIRES: nullifier_without_secret
    // Using placeholder - real circuit would use: component hasher = Poseidon(1);
    nullifier <== externalNullifier;  // Simplified for testing
}

component main { public [externalNullifier] } = WeakNullifier();
