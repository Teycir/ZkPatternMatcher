pragma circom 2.0.0;

// SAFE: direction bits constrained, root constrained
template SafeMerkle(levels) {
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    signal input root;

    signal hashes[levels + 1];
    hashes[0] <== leaf;

    for (var i = 0; i < levels; i++) {
        // Binary constraint on direction bit
        pathIndices[i] * (pathIndices[i] - 1) === 0;

        // Correct mux pattern
        hashes[i + 1] <== hashes[i] * (1 - pathIndices[i]) + pathElements[i] * pathIndices[i];
    }

    // Correct: constraint not comparison
    hashes[levels] === root;
}

component main { public [root, leaf] } = SafeMerkle(4);
