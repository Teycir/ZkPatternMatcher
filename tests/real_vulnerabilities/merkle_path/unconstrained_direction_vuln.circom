pragma circom 2.0.0;

// VULNERABLE: path direction bits not binary-constrained
template WeakMerkle(levels) {
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels];   // <-- no binary constraint added
    signal input root;
    signal output valid;

    signal hashes[levels + 1];
    hashes[0] <== leaf;

    for (var i = 0; i < levels; i++) {
        // FIRES: unconstrained_path_direction (pathIndices[i] not binary-constrained)
        // Simplified mux pattern
        hashes[i + 1] <== hashes[i] * pathIndices[i] + pathElements[i] * (1 - pathIndices[i]);
    }

    // FIRES: merkle_root_comparison_not_constraint — == instead of ===
    valid <== (hashes[levels] == root) ? 1 : 0;
}

component main { public [root, leaf] } = WeakMerkle(4);
