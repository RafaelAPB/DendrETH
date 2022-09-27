pragma circom 2.0.3;

include "hash_tree_root.circom";
include "compress.circom";
include "aggregate_bitmask.circom";
include "is_supermajority.circom";
include "is_valid_merkle_branch.circom";
include "../../../vendor/circom-pairing/circuits/bls_signature.circom";

template LightClient(N) {
  var K = 7;
  signal input prevHeaderHashNum[2];
  signal input nextHeaderHashNum[2];

  signal input slot[256];
  signal input proposer_index[256];
  signal input parent_root[256];
  signal input state_root[256];
  signal input body_root[256];

  signal input fork_version[32];

  signal input prevHeaderState[256];

  signal input points[N][2][K];
  signal input aggregatedKey[384];
  signal input branch[5][256];

  signal input bitmask[N];
  signal input signature[2][2][K];

  signal output hashTreeRoot[2];

  var prevHeaderHash[256];
  var nextHeaderHash[256];

  component num2bits1 = Num2Bits(253);
  num2bits1.in <== prevHeaderHashNum[0];

  component num2bits2 = Num2Bits(3);
  num2bits2.in <== prevHeaderHashNum[1];

  for(var i = 0; i < 253; i++) {
    prevHeaderHash[i] <== num2bits1.out[252 - i];
  }

  for(var i = 253; i < 256; i++) {
    prevHeaderHash[i] <== num2bits2.out[255 - i];
  }

  component num2bits3 = Num2Bits(253);
  num2bits3.in <== nextHeaderHashNum[0];

  for(var i = 0; i < 253; i++) {
    nextHeaderHash[i] <== num2bits3.out[253 - i];
  }

  component num2bits4 = Num2Bits(3);
  num2bits4.in <== nextHeaderHashNum[1];

  for(var i = 253; i < 256; i++) {
    nextHeaderHash[i] <== num2bits4.out[255 - i];
  }

  component isSuperMajority = IsSuperMajority(N);

  for(var i = 0; i < N; i++) {
    isSuperMajority.bitmask[i] <== bitmask[i];
  }

  isSuperMajority.out === 1;

  component hash_tree_root_beacon = HashTreeRootBeaconHeader();

  for(var i = 0; i < 256; i++) {
    hash_tree_root_beacon.slot[i] <== slot[i];
  }

  for(var i = 0; i < 256; i++) {
    hash_tree_root_beacon.proposer_index[i] <== proposer_index[i];
  }

  for(var i = 0; i < 256; i++) {
    hash_tree_root_beacon.parent_root[i] <== parent_root[i];
  }

  for(var i = 0; i < 256; i++) {
    hash_tree_root_beacon.state_root[i] <== state_root[i];
  }

  for(var i = 0; i < 256; i++) {
    hash_tree_root_beacon.body_root[i] <== body_root[i];
  }

  for(var i = 0; i < 256; i++) {
    hash_tree_root_beacon.blockHash[i] === prevHeaderHash[i];
  }

  component computeDomain = ComputeDomain();

  for(var i = 0; i < 32; i++) {
    computeDomain.fork_version[i] <== fork_version[i];
  }

  component computeSigningRoot = ComputeSigningRoot();

  for(var i = 0; i < 256; i++) {
    computeSigningRoot.headerHash[i] <== nextHeaderHash[i];
  }

  for(var i = 0; i < 256; i++) {
    computeSigningRoot.domain[i] <== computeDomain.domain[i];
  }

  component hashToField = HashToField();

  for(var i = 0; i < 256; i++) {
    hashToField.in[i] <== computeSigningRoot.signing_root[i];
  }

  component hasher = HashTreeRoot(N);
  component compress[N];

  for(var i = 0; i < N; i++) {
    compress[i] = Compress();

    for(var j = 0; j < 2; j++) {
      for(var k = 0; k < K; k++) {
        compress[i].point[j][k] <== points[i][j][k];
      }
    }

    for(var j = 0; j < 384; j++) {
      hasher.points[i][j] <== compress[i].bits[j];
    }
  }

  for(var i = 0; i < 384; i++) {
    hasher.aggregatedKey[i] <== aggregatedKey[i];
  }

  component isValidMerkleBranch = IsValidMerkleBranch(5);

  for(var i = 0; i < 5; i++) {
    for(var j = 0; j < 256; j++) {
      isValidMerkleBranch.branch[i][j] <== branch[i][j];
    }
  }

  for(var i = 0; i < 256; i++) {
    isValidMerkleBranch.leaf[i] <== hasher.out[i];
  }

  for(var i = 0; i < 256; i++) {
    isValidMerkleBranch.root[i] <== prevHeaderState[i];
  }

  isValidMerkleBranch.index <== 55;

  isValidMerkleBranch.out === 1;

  component aggregateKeys = AggregateKeysBitmask(N);

  for(var i = 0; i < N; i++) {
    for(var j = 0; j < 2; j++) {
      for(var k = 0; k < K; k++) {
        aggregateKeys.points[i][j][k] <== points[i][j][k];
      }
    }
  }

  for(var i = 0; i < N; i++) {
    aggregateKeys.bitmask[i] <== bitmask[i];
  }

  component verify = CoreVerifyPubkeyG1(55, K);

  for(var j = 0; j < 2; j++) {
    for(var k = 0; k < K; k++) {
      verify.pubkey[j][k] <== aggregateKeys.out[j][k];
    }
  }

  for(var i = 0; i < 2; i++) {
    for(var j = 0; j < 2; j++) {
      for(var k = 0; k < K; k++) {
        verify.signature[i][j][k] <== signature[i][j][k];
        verify.hash[i][j][k] <== hashToField.out[i][j][k];
      }
    }
  }

  component bits2Num[2];
  bits2Num[0] = Bits2Num(253);
  for(var i = 0; i < 253; i++) {
    bits2Num[0].in[i] <== hasher.out[252-i];
  }
  hashTreeRoot[1] <== bits2Num[0].out;

  bits2Num[1] = Bits2Num(3);

  for(var i = 0; i < 3; i++){
    bits2Num[1].in[i] <== hasher.out[255-i];
  }

  hashTreeRoot[0] <== bits2Num[1].out;
}
