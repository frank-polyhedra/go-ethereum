use std::collections::BTreeMap;

use ethabi::Token;
use hypr_algebra::bn254::BN254Scalar;
use hypr_api::{
    algebra::prelude::*,
    anon_xfr::{
        abar_to_abar::{finish_anon_xfr_note, init_anon_xfr_note},
        ar_to_abar::gen_ar_to_abar_note,
        decrypt_memo,
        ownership::{finish_ownership_note, init_ownership_note},
        AXfrAddressFoldingInstance, AXfrPlonkPf,
    },
    keys::{KeyPair, PublicKey},
    parameters::{AddressFormat, ProverParams},
    structs::{
        AnonAssetRecord, AssetType, AxfrOwnerMemo, MTLeafInfo, MTNode, OpenAnonAssetRecord,
        OpenAnonAssetRecordBuilder, ASSET_TYPE_LENGTH,
    },
};
use hypr_crypto::anemoi_jive::{AnemoiJive, AnemoiJive254, ANEMOI_JIVE_BN254_SALTS};
use libsecp256k1::SecretKey;
use precompiles::anon::__precompile_anonymous_verify;
use primitive_types::U256;
use rand_chacha::ChaChaRng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_512};

#[derive(Debug, Serialize, Deserialize)]
pub struct T2A {
    pub target: KeyPair,
    pub hash: [u8; 32],
    pub amount: u128,
    pub asset: AssetType,
    pub commitment: BN254Scalar,
    pub memo: AxfrOwnerMemo,
    pub proof: AXfrPlonkPf,
}
fn build_t2a<R: CryptoRng + RngCore>(prng: &mut R) -> T2A {
    let asset = AssetType([0u8; ASSET_TYPE_LENGTH]);

    let target = {
        let bytes = SecretKey::random(prng).serialize();
        KeyPair::generate_secp256k1_from_bytes(&bytes).unwrap()
    };
    let hash = [0u8; 32]; //防重放
    let mut hasher = Sha3_512::new();
    hasher.update(&hash);

    let params = ProverParams::gen_ar_to_abar().unwrap();
    let amount = 10000;
    let note = gen_ar_to_abar_note(prng, &params, asset, amount, &target.get_pk(), hasher).unwrap();

    T2A {
        target,
        hash,
        amount: note.amount,
        asset: note.asset,
        commitment: note.output.commitment,
        memo: note.memo,
        proof: note.proof,
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Ownership {
    pub root_version: u64,
    pub amount: u128,
    pub asset: AssetType,
    pub nullifier: BN254Scalar,
    pub proof: AXfrPlonkPf,
    pub folding_instance: AXfrAddressFoldingInstance,
    pub hash: [u8; 32],
}

fn build_ownership<R: CryptoRng + RngCore>(
    prng: &mut R,
    t2a: T2A,
    path_nodes: Vec<MTNode>,
    root: BN254Scalar,
) -> Ownership {
    let (amount, asset_type, blind) = decrypt_memo(
        &t2a.memo,
        &t2a.target,
        &AnonAssetRecord {
            commitment: t2a.commitment,
        },
    )
    .unwrap();

    let mut oabar = OpenAnonAssetRecord {
        amount,
        asset_type,
        blind,
        pub_key: t2a.target.get_pk(),
        owner_memo: None,
        mt_leaf_info: None,
    };

    let mut mt_leaf_info = MTLeafInfo::default();
    mt_leaf_info.path.nodes = path_nodes;
    mt_leaf_info.root = root;
    mt_leaf_info.root_version = 0;
    mt_leaf_info.uid = 0; //合约里面的commitment的索引

    oabar.update_mt_leaf_info(mt_leaf_info);

    // pre note
    let pre_note = init_ownership_note(&oabar, &t2a.target).unwrap();

    let hash = [1u8; 32]; //防重放
    let mut hasher = Sha3_512::new();
    hasher.update(&hash);
    hasher.update(&bincode::serialize(&pre_note.body).unwrap());

    // finiash note
    let params = ProverParams::gen_ownership(AddressFormat::SECP256K1).unwrap();

    let note = finish_ownership_note(prng, &params, pre_note, hasher).unwrap();

    Ownership {
        root_version: note.body.merkle_root_version,
        amount: note.body.amount,
        asset: note.body.asset,
        nullifier: note.body.input,
        proof: note.proof,
        folding_instance: note.folding_instance,
        hash,
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct A2A {
    pub root_version: u64,
    pub fee_amount: u128,
    pub fee_asset: AssetType,
    pub transparent_amount: u128,
    pub transparent_asset: AssetType,
    pub hash: [u8; 32],
    pub nullifiers: Vec<BN254Scalar>,
    pub commitments: Vec<AnonAssetRecord>,
    pub memos: Vec<AxfrOwnerMemo>,
    pub proof: AXfrPlonkPf,
    pub folding_instance: AXfrAddressFoldingInstance,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Output {
    pub amount: u128,
    pub asset: AssetType,
    pub public_key: PublicKey,
}

pub fn build_a2a<R: CryptoRng + RngCore>(
    prng: &mut R,
    t2a: T2A,
    path_nodes: Vec<MTNode>,
    root: BN254Scalar,
    fee_amount: u128,
    transparent_amount: u128,
    outputs: Vec<Output>,
) -> A2A {
    let (amount, asset_type, blind) = decrypt_memo(
        &t2a.memo,
        &t2a.target,
        &AnonAssetRecord {
            commitment: t2a.commitment,
        },
    )
    .unwrap();

    let mut oabar = OpenAnonAssetRecord {
        amount,
        asset_type,
        blind,
        pub_key: t2a.target.get_pk(),
        owner_memo: None,
        mt_leaf_info: None,
    };

    let mut mt_leaf_info = MTLeafInfo::default();
    mt_leaf_info.path.nodes = path_nodes;
    mt_leaf_info.root = root;
    mt_leaf_info.root_version = 0;
    mt_leaf_info.uid = 1; //合约里面的commitment的索引

    oabar.update_mt_leaf_info(mt_leaf_info);
    let input_oabars = vec![oabar];

    let mut output_oabars = vec![];
    for output in outputs {
        output_oabars.push(
            OpenAnonAssetRecordBuilder::new()
                .amount(output.amount)
                .asset_type(output.asset)
                .pub_key(&output.public_key)
                .finalize(prng)
                .unwrap()
                .build()
                .unwrap(),
        );
    }

    let (inputs_len, outputs_len) = (input_oabars.len(), output_oabars.len());

    // pre note
    let pre_note = init_anon_xfr_note(
        &input_oabars,
        &output_oabars,
        fee_amount,
        t2a.asset, //手续费可以是不同的类型
        transparent_amount,
        t2a.asset,
        &t2a.target,
    )
    .unwrap();

    let hash = [2u8; 32]; //防重放
    let mut hasher = Sha3_512::new();
    hasher.update(&hash);
    hasher.update(&bincode::serialize(&pre_note.body).unwrap());

    // finish note
    let params =
        ProverParams::gen_abar_to_abar(inputs_len, outputs_len, AddressFormat::SECP256K1).unwrap();

    let note = finish_anon_xfr_note(prng, &params, pre_note, hasher).unwrap();

    A2A {
        root_version: note.body.merkle_root_version,
        fee_amount: note.body.fee,
        fee_asset: note.body.fee_type,
        transparent_amount: note.body.transparent,
        transparent_asset: note.body.transparent_type,
        hash,
        nullifiers: note.body.inputs,
        commitments: note.body.outputs,
        memos: note.body.owner_memos,
        proof: note.proof,
        folding_instance: note.folding_instance,
    }
}

pub struct MerkleTree {
    leafs: BTreeMap<u64, BN254Scalar>,
    latest_leaf: u64,
    merkle_height: BTreeMap<BN254Scalar, u64>,
    current_merkle_height: u64,
}

#[derive(Debug)]
pub enum TreePath {
    Left,
    Middle,
    Right,
}

impl MerkleTree {
    // total merkle depth
    const TREE_DEPTH: u64 = 25;

    // merkle data pos start
    const LEAF_START: u64 = 423644304721;

    fn new() -> Self {
        Self {
            leafs: BTreeMap::new(),
            latest_leaf: 0,
            merkle_height: BTreeMap::new(),
            current_merkle_height: 1,
        }
    }

    fn set_merkle(&mut self, uid: u64, merkle: BN254Scalar) {
        self.leafs.insert(uid, merkle);
    }

    fn append(&mut self, leaf: BN254Scalar) -> u64 {
        let uid = Self::LEAF_START + self.latest_leaf;
        self.set_merkle(uid, leaf);
        self.latest_leaf += 1;
        uid
    }

    // set merkle root as `r`
    fn set_root(&mut self, r: BN254Scalar) {
        self.leafs.insert(0, r);
        self.merkle_height.insert(r, self.current_merkle_height);
        self.current_merkle_height += 1;
    }

    fn root(&self) -> BN254Scalar {
        self.leafs.get(&0).unwrap().clone()
    }

    fn update_merkle_tree(&mut self, cid: u64, commitment: &BN254Scalar) {
        let mut new_root =
            AnemoiJive254::eval_variable_length_hash(&[BN254Scalar::from(cid), *commitment]);

        let mut left;
        let mut right;
        let mut mid;
        let mut key = self.append(new_root);
        let mut mod_num;
        for i in 0..Self::TREE_DEPTH {
            self.set_merkle(key, new_root);
            mod_num = key % 3;
            if mod_num == 0 {
                left = key - 2;
                mid = key - 1;
                right = key;
                key = key / 3 - 1;
            } else if mod_num == 1 {
                left = key;
                mid = key + 1;
                right = key + 2;
                key = key / 3;
            } else {
                left = key - 1;
                mid = key;
                right = key + 1;
                key = key / 3;
            }

            new_root = AnemoiJive254::eval_jive(
                &[
                    self.leafs.get(&left).cloned().unwrap_or_default(),
                    self.leafs.get(&mid).cloned().unwrap_or_default(),
                ],
                &[
                    self.leafs.get(&right).cloned().unwrap_or_default(),
                    ANEMOI_JIVE_BN254_SALTS[i as usize],
                ],
            );
        }

        self.set_root(new_root);
    }

    fn get_path_keys(cid: u64) -> Vec<(u64, TreePath)> {
        let mut keys = vec![];
        let mut key = Self::LEAF_START + cid;

        for _ in 0..=Self::TREE_DEPTH {
            let rem = key % 3;
            match rem {
                1 => {
                    keys.push((key, TreePath::Left));
                    key /= 3;
                }
                2 => {
                    keys.push((key, TreePath::Middle));
                    key /= 3;
                }
                0 => {
                    keys.push((key, TreePath::Right));
                    key = if key != 0 { key / 3 - 1 } else { 0 };
                }
                _ => {}
            }
        }
        keys
    }

    fn proof(&self, cid: u64) -> Vec<MTNode> {
        let keys = Self::get_path_keys(cid);

        keys[0..Self::TREE_DEPTH as usize]
            .iter()
            .map(|(key_id, path)| {
                let mut node = MTNode {
                    left: Default::default(),
                    mid: Default::default(),
                    right: Default::default(),
                    is_left_child: 0,
                    is_mid_child: 0,
                    is_right_child: 0,
                };

                let (left_key_id, mid_key_id, right_key_id) = match path {
                    TreePath::Left => {
                        node.is_left_child = 1;
                        (*key_id, key_id + 1, key_id + 2)
                    }
                    TreePath::Middle => {
                        node.is_mid_child = 1;
                        (key_id - 1, *key_id, key_id + 1)
                    }
                    TreePath::Right => {
                        node.is_right_child = 1;
                        (key_id - 2, key_id - 1, *key_id)
                    }
                };

                node.left = self.leafs.get(&left_key_id).cloned().unwrap_or_default();

                node.mid = self.leafs.get(&mid_key_id).cloned().unwrap_or_default();

                node.right = self.leafs.get(&right_key_id).cloned().unwrap_or_default();

                node
            })
            .collect()
    }
}

fn main() {
    let mut prng = ChaChaRng::from_entropy();
    let mut merkle_tree = MerkleTree::new();
    {
        let t2a = build_t2a(&mut prng);
        {
            let mut data = vec![0x29, 0xef, 0xb1, 0x48];
            let bytes = ethabi::encode(&[
                Token::Array(vec![Token::FixedBytes(t2a.commitment.to_bytes())]),
                Token::Array(vec![Token::FixedBytes(t2a.asset.to_bytes())]),
                Token::Array(vec![Token::Uint(U256::from(t2a.amount))]),
                Token::Array(vec![Token::Bytes(bincode::serialize(&t2a.proof).unwrap())]),
                Token::Array(vec![Token::Bytes(t2a.memo.to_bytes())]),
                Token::Array(vec![Token::FixedBytes(t2a.hash.to_vec())]),
            ]);
            data.extend(bytes);
            if 0 != __precompile_anonymous_verify(data.as_ptr(), data.len()) {
                panic!("verify t2a error");
            } else {
                println!("verify t2a success")
            }
        }
        let cid = 0;
        merkle_tree.update_merkle_tree(cid, &t2a.commitment);
        let path_nodes = merkle_tree.proof(cid);
        let root = merkle_tree.root();
        let ownership = build_ownership(&mut prng, t2a, path_nodes, root);
        {
            let mut data = vec![0x29, 0x7d, 0xb2, 0x29];
            let bytes = ethabi::encode(&[
                Token::Uint(U256::from(ownership.root_version)),
                Token::Uint(U256::from(ownership.amount)),
                Token::Bytes(ownership.asset.to_bytes()),
                Token::Bytes(ownership.nullifier.to_bytes()),
                Token::Bytes(
                    bincode::serialize(&(ownership.proof, ownership.folding_instance)).unwrap(),
                ),
                Token::FixedBytes(root.to_bytes()),
                Token::Bytes(ownership.hash.to_vec()),
            ]);
            data.extend(bytes);
            if 0 != __precompile_anonymous_verify(data.as_ptr(), data.len()) {
                panic!("verify ownership error");
            } else {
                println!("verify ownership success")
            }
        }
    }
    {
        let t2a = build_t2a(&mut prng);
        {
            let mut data = vec![0x29, 0xef, 0xb1, 0x48];
            let bytes = ethabi::encode(&[
                Token::Array(vec![Token::FixedBytes(t2a.commitment.to_bytes())]),
                Token::Array(vec![Token::FixedBytes(t2a.asset.to_bytes())]),
                Token::Array(vec![Token::Uint(U256::from(t2a.amount))]),
                Token::Array(vec![Token::Bytes(bincode::serialize(&t2a.proof).unwrap())]),
                Token::Array(vec![Token::Bytes(t2a.memo.to_bytes())]),
                Token::Array(vec![Token::FixedBytes(t2a.hash.to_vec())]),
            ]);
            data.extend(bytes);
            if 0 != __precompile_anonymous_verify(data.as_ptr(), data.len()) {
                panic!("verify t2a error");
            } else {
                println!("verify t2a success")
            }
        }

        let cid = 1;
        merkle_tree.update_merkle_tree(cid, &t2a.commitment);

        let path_nodes = merkle_tree.proof(cid);
        let root = merkle_tree.root();
        let public_key = {
            let bytes = SecretKey::random(&mut prng).serialize();
            KeyPair::generate_secp256k1_from_bytes(&bytes)
                .unwrap()
                .get_pk()
        };

        let asset = t2a.asset;
        let a2a = build_a2a(
            &mut prng,
            t2a,
            path_nodes,
            root,
            1000,
            2000,
            vec![Output {
                amount: 7000,
                asset,
                public_key,
            }],
        );
        {
            let mut data = vec![0xd0, 0xb8, 0x51, 0xef];

            let bytes = ethabi::encode(&[
                Token::Array(vec![Token::Array(
                    a2a.nullifiers
                        .iter()
                        .map(|v| Token::FixedBytes(v.to_bytes()))
                        .collect::<Vec<_>>(),
                )]),
                Token::Array(vec![Token::Array(
                    a2a.commitments
                        .iter()
                        .map(|v| Token::FixedBytes(v.commitment.to_bytes()))
                        .collect::<Vec<_>>(),
                )]),
                Token::Array(vec![Token::FixedBytes(a2a.fee_asset.to_bytes())]),
                Token::Array(vec![Token::Uint(U256::from(a2a.fee_amount))]),
                Token::Array(vec![Token::Uint(U256::from(a2a.root_version))]),
                Token::Array(vec![Token::FixedBytes(root.to_bytes())]),
                Token::Array(vec![Token::FixedBytes(a2a.transparent_asset.to_bytes())]),
                Token::Array(vec![Token::Uint(U256::from(a2a.transparent_amount))]),
                Token::Array(vec![Token::FixedBytes(a2a.hash.to_vec())]),
                Token::Array(vec![Token::Array(
                    a2a.memos
                        .iter()
                        .map(|v| Token::Bytes(v.to_bytes()))
                        .collect::<Vec<_>>(),
                )]),
                Token::Array(vec![Token::Bytes(
                    bincode::serialize(&(a2a.proof, a2a.folding_instance)).unwrap(),
                )]),
            ]);
            data.extend(bytes);
            if 0 != __precompile_anonymous_verify(data.as_ptr(), data.len()) {
                panic!("verify a2a error");
            } else {
                println!("verify a2a success")
            }
        }
    }
}
