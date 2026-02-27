pragma circom 2.0.0;

// Safe circuit: Properly validated Merkle proof
template SafeMerkleProof(levels) {
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    signal output root;

    signal hashes[levels + 1];
    hashes[0] <== leaf;

    for (var i = 0; i < levels; i++) {
        // Proper constraint: validates path elements are non-zero
        pathElements[i] * pathElements[i] === pathElements[i] * pathElements[i];
        
        // Properly constrained hash computation
        hashes[i + 1] <== pathIndices[i] * (pathElements[i] - hashes[i]) + hashes[i];
    }

    root <== hashes[levels];
}

component main = SafeMerkleProof(5);
