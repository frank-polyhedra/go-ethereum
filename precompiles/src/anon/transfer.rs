use alloc::{boxed::Box, vec::Vec};
use ethabi::ParamType;
use hypr_algebra::{bn254::BN254Scalar, serialization::FromToBytes};
use hypr_api::{
    anon_xfr::{
        abar_to_abar::{verify_anon_xfr_note, AXfrBody, AXfrNote},
        AXfrAddressFoldingInstance, AXfrPlonkPf,
    },
    parameters::VerifierParams,
    structs::{AnonAssetRecord, AxfrOwnerMemo},
};
use primitive_types::U256;
use sha3::{Digest, Sha3_512};

use crate::{
    utils::{self, bytes_asset, check_address_format_from_folding},
    Error, Result,
};

pub struct Transfer {
    nullifiers: Vec<Vec<[u8; 32]>>,
    commitments: Vec<Vec<[u8; 32]>>,
    asset: Vec<[u8; 32]>,
    fee_amount: Vec<U256>,
    root_version: Vec<u64>,
    root: Vec<[u8; 32]>,
    transparent_asset: Vec<[u8; 32]>,
    transparent_amount: Vec<U256>,
    hash: Vec<[u8; 32]>,
    memos: Vec<Vec<Vec<u8>>>,
    proof: Vec<Vec<u8>>,
}

impl Transfer {
    fn params_type() -> [ParamType; 11] {
        [
            ParamType::Array(Box::new(ParamType::Array(Box::new(ParamType::FixedBytes(
                32,
            ))))),
            ParamType::Array(Box::new(ParamType::Array(Box::new(ParamType::FixedBytes(
                32,
            ))))),
            ParamType::Array(Box::new(ParamType::FixedBytes(32))),
            ParamType::Array(Box::new(ParamType::Uint(256))),
            ParamType::Array(Box::new(ParamType::Uint(64))),
            ParamType::Array(Box::new(ParamType::FixedBytes(32))),
            ParamType::Array(Box::new(ParamType::FixedBytes(32))),
            ParamType::Array(Box::new(ParamType::Uint(256))),
            ParamType::Array(Box::new(ParamType::FixedBytes(32))),
            ParamType::Array(Box::new(ParamType::Array(Box::new(ParamType::Bytes)))),
            ParamType::Array(Box::new(ParamType::Bytes)),
        ]
    }

    pub fn new(data: &[u8]) -> Result<Self> {
        let tokens =
            ethabi::decode(&Self::params_type(), data).map_err(|_| Error::ParseDataFailed)?;

        let nullifiers = tokens
            .get(0)
            .and_then(|v| v.clone().into_array())
            .and_then(|vs| {
                vs.iter()
                    .map(|v| utils::into_bytes32_array(Some(v.clone())))
                    .collect::<Option<Vec<_>>>()
            })
            .ok_or(Error::ParseDataFailed)?;

        let commitments = tokens
            .get(1)
            .and_then(|v| v.clone().into_array())
            .and_then(|vs| {
                vs.iter()
                    .map(|v| utils::into_bytes32_array(Some(v.clone())))
                    .collect::<Option<Vec<_>>>()
            })
            .ok_or(Error::ParseDataFailed)?;

        let assets = tokens
            .get(2)
            .and_then(|v| v.clone().into_array())
            .and_then(|vs| {
                vs.iter()
                    .map(|v| utils::into_bytes32(Some(v.clone())))
                    .collect::<Option<Vec<_>>>()
            })
            .ok_or(Error::ParseDataFailed)?;

        let fee_amounts = tokens
            .get(3)
            .and_then(|v| v.clone().into_array())
            .and_then(|vs| {
                vs.iter()
                    .map(|v| utils::into_uint256(Some(v.clone())))
                    .collect::<Option<Vec<_>>>()
            })
            .ok_or(Error::ParseDataFailed)?;

        let root_versions = tokens
            .get(4)
            .and_then(|v| v.clone().into_array())
            .and_then(|vs| {
                vs.iter()
                    .map(|v| utils::into_uint(Some(v.clone())).map(|ver| ver as u64))
                    .collect::<Option<Vec<_>>>()
            })
            .ok_or(Error::ParseDataFailed)?;

        let roots = tokens
            .get(5)
            .and_then(|v| v.clone().into_array())
            .and_then(|vs| {
                vs.iter()
                    .map(|v| utils::into_bytes32(Some(v.clone())))
                    .collect::<Option<Vec<_>>>()
            })
            .ok_or(Error::ParseDataFailed)?;

        let transparent_assets = tokens
            .get(6)
            .and_then(|v| v.clone().into_array())
            .and_then(|vs| {
                vs.iter()
                    .map(|v| utils::into_bytes32(Some(v.clone())))
                    .collect::<Option<Vec<_>>>()
            })
            .ok_or(Error::ParseDataFailed)?;

        let transparent_amounts = tokens
            .get(7)
            .and_then(|v| v.clone().into_array())
            .and_then(|vs| {
                vs.iter()
                    .map(|v| utils::into_uint256(Some(v.clone())))
                    .collect::<Option<Vec<_>>>()
            })
            .ok_or(Error::ParseDataFailed)?;

        let hashs = tokens
            .get(8)
            .and_then(|v| v.clone().into_array())
            .and_then(|vs| {
                vs.iter()
                    .map(|v| utils::into_bytes32(Some(v.clone())))
                    .collect::<Option<Vec<_>>>()
            })
            .ok_or(Error::ParseDataFailed)?;

        let memoses = tokens
            .get(9)
            .and_then(|v| v.clone().into_array())
            .and_then(|vs| {
                vs.iter()
                    .map(|v| utils::into_bytes_array(Some(v.clone())))
                    .collect::<Option<Vec<_>>>()
            })
            .ok_or(Error::ParseDataFailed)?;

        let proofs = tokens
            .get(10)
            .and_then(|v| v.clone().into_array())
            .and_then(|vs| {
                vs.iter()
                    .map(|v| utils::into_bytes(Some(v.clone())))
                    .collect::<Option<Vec<_>>>()
            })
            .ok_or(Error::ParseDataFailed)?;

        let r = Self {
            nullifiers,
            commitments,
            asset: assets,
            fee_amount: fee_amounts,
            root_version: root_versions,
            root: roots,
            transparent_asset: transparent_assets,
            transparent_amount: transparent_amounts,
            hash: hashs,
            memos: memoses,
            proof: proofs,
        };
        r.require()?;

        Ok(r)
    }

    pub fn require(&self) -> Result<()> {
        let length = self.nullifiers.len();
        if self.commitments.len() == length
            && self.asset.len() == length
            && self.fee_amount.len() == length
            && self.root_version.len() == length
            && self.root.len() == length
            && self.transparent_asset.len() == length
            && self.transparent_amount.len() == length
            && self.hash.len() == length
            && self.memos.len() == length
            && self.proof.len() == length
        {
            Ok(())
        } else {
            Err(Error::UnsupportInputsOutputs)
        }
    }

    pub fn check(self) -> Result<()> {
        let length = self.nullifiers.len();
        let mut res = Vec::new();
        for i in 0..length {
            res.push(verify_atoa(
                self.nullifiers.get(i).cloned().unwrap(),
                self.commitments.get(i).cloned().unwrap(),
                self.root.get(i).cloned().unwrap(),
                self.proof.get(i).cloned().unwrap(),
                self.fee_amount[i].as_u128(),
                self.asset[i],
                self.transparent_asset[i],
                self.root_version[i],
                self.transparent_amount[i].as_u128(),
                self.memos.get(i).cloned().unwrap(),
                self.hash[i],
            ));
        }

        for r in res {
            r?
        }
        Ok(())
    }

    pub fn gas(self) -> u64 {
        let length = self.nullifiers.len();
        let mut gas: u64 = 0;
        for i in 0..length {
            gas += TRANSFER_PER_INPUT * self.nullifiers.get(i).cloned().unwrap().len() as u64
                + TRANSFER_PER_OUTPUT * self.commitments.get(i).cloned().unwrap().len() as u64
        }
        gas
    }
}

pub const TRANSFER_PER_INPUT: u64 = 4000;
pub const TRANSFER_PER_OUTPUT: u64 = 30000;

#[allow(clippy::too_many_arguments)]
fn verify_atoa(
    nullifiers: Vec<[u8; 32]>,
    commitments: Vec<[u8; 32]>,
    merkle_root: [u8; 32],
    proof: Vec<u8>,
    fee: u128,
    fee_asset: [u8; 32],
    transparent_asset: [u8; 32],
    root_version: u64,
    transparent: u128,
    memos: Vec<Vec<u8>>,
    hash: [u8; 32],
) -> Result<()> {
    let (proof, folding_instance): (AXfrPlonkPf, AXfrAddressFoldingInstance) =
        bincode::deserialize(&proof).map_err(|_| Error::ProofDecodeFailed)?;

    let address_format = check_address_format_from_folding(&folding_instance);
    let fee_type = bytes_asset(&fee_asset)?;
    let transparent_type = bytes_asset(&transparent_asset)?;
    let merkle_root = BN254Scalar::from_bytes(&merkle_root).map_err(|_| Error::ParseDataFailed)?;

    let mut inputs = Vec::new();
    for bytes in nullifiers.iter() {
        inputs.push(BN254Scalar::from_bytes(bytes).map_err(|_| Error::ParseDataFailed)?);
    }

    let mut outputs = Vec::new();
    for bytes in commitments.iter() {
        outputs.push(AnonAssetRecord {
            commitment: BN254Scalar::from_bytes(bytes).map_err(|_| Error::ParseDataFailed)?,
        });
    }
    let (inputs_len, outputs_len) = (inputs.len(), outputs.len());
    let note = AXfrNote {
        body: AXfrBody {
            inputs,
            outputs,
            merkle_root,
            merkle_root_version: root_version,
            fee,
            fee_type,
            transparent,
            transparent_type,
            owner_memos: memos
                .iter()
                .map(|bytes| AxfrOwnerMemo::from_bytes(bytes))
                .collect(),
        },
        proof,
        folding_instance,
    };

    let mut hasher = Sha3_512::new();
    hasher.update(hash);
    hasher.update(&bincode::serialize(&note.body).map_err(|_| Error::ParseDataFailed)?);

    let params = VerifierParams::get_abar_to_abar(inputs_len, outputs_len, address_format)
        .map_err(|_| Error::FailedToLoadVerifierParams)?;

    verify_anon_xfr_note(&params, &note, &merkle_root, hasher)
        .map_err(|_| Error::ProofVerificationFailed)
}

#[cfg(test)]
mod test {
    use super::Transfer;

    #[test]
    fn test_len_1() {
        let encode = hex::decode("0000000000000000000000000000000000000000000000000000000000000180000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002a000000000000000000000000000000000000000000000000000000000000002e00000000000000000000000000000000000000000000000000000000000000320000000000000000000000000000000000000000000000000000000000000036000000000000000000000000000000000000000000000000000000000000003a000000000000000000000000000000000000000000000000000000000000003e00000000000000000000000000000000000000000000000000000000000000420000000000000000000000000000000000000000000000000000000000000046000000000000000000000000000000000000000000000000000000000000004a000000000000000000000000000000000000000000000000000000000000006c00000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000010e180ea3540922bfaba8fb57ab1f75b5745322bfb4de7e3eaf650cd96eae832a0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000028b1a51ca179871d765c5b362ad6fbd5432cd8a57324425761647ec53ed046d1b4ffddb4540ac70c38c4a7799db194cf0d4957fa89b373eeeb134051c874776200000000000000000000000000000000000000000000000000000000000000001000000000000000000000000cb738b24741d515b6323d271f1f946acb0a7fc1b00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000090000000000000000000000000000000000000000000000000000000000000001f088fd33a7f1fcd5b5940e2621455ce0f3ca89080c03ea73d53f9addd2f160250000000000000000000000000000000000000000000000000000000000000001000000000000000000000000e527537e9eb03226ac521add09c77e98b84ead130000000000000000000000000000000000000000000000000000000000000001000000000000000000000000cb738b24741d515b6323d271f1f946acb0a7fc1b000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001a5d30a174c1f6e6411306e0647a1bc00a89af6e884d235c067ce02aec5e510440000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000811cc1c6cdd03a31937f0a4892104574c614e423998766fa6e2e1f0eff51a137d68000d699673a1db865308f9e7fee1958c7d34e2004892e3e9491b8c2ba6c20a2505dcb690adbb8cdb500151a4a7bd88fbd218219c85e71c7476ec249b2a09ab7bca1a11777f3404f8c5b967274ec58ec85c69dda225a3c7f95c222016a7c2f913c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000081f5212c1bef35598afca3ed8e12fb2c3d2af58fde7596e713de67a6871fb8000180a2175a0c7b1f271753398ab62ed7d18701d2ac49e6f04743fac3e974e8d48695c764a0d2e48795b85c204ae69d039cdb1ebce832ab3a134ce6c6c65b5230842937209570ea5dc33357f29d674d573d4a40504aeb2cceb7bcde8ee155ab58aa1b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000bab05000000000000002000000000000000b7c98a7b126ee976767b31fa27fbee824992ed97d0c0e71d215a9f6d642de12c20000000000000009edb4e11bb9dad8f9cafae29b9cf986bcf48f488b72941ad1ddfbfef59bb598e2000000000000000c6f7fafe422ceaf269e0e72a5547837df3f8168ec645aa10db140858c8ee0f942000000000000000749ca2333266253663d0ce6236b5a295b6a40c394f8740d61107da4e5912242d20000000000000007f427c68d83e7f192ba8844a96056a4ff0fbff14d30adfc9e1186e165139612205000000000000002000000000000000ef69efe0ec3c0b2cd28ee911b28e70119a52936a4ea863bc7b8e9197136181072000000000000000337dceecd8fdefc03efd437bef5d1934987fd5aa4155627603817d777133bd12200000000000000012ef05f65f349914fedec4139298cd3b38aaf3f0693b3e8ce7052b9e47ce6aa3200000000000000006c50ae6bde42fd408e796e393727a6802c347bfdad749f25ba01f6fda5754222000000000000000b1cd60b7357fbbe79264bd7b003d5002b21e3c5383020c461c61d4bf6616168d20000000000000000a7346fa8734596c9c825dcb8a787db7d19a0e3ffb00c8cf4e1ee4fe475d20042000000000000000065b736b1246e441bcc5017fff58b2da4d2e2d83c6dc74ab4481ff294a76fa2b20000000000000003fbd42ae4802ac527839fb1b1f6667010ca2155ac760d7552a77de91b70bba19050000000000000020000000000000000611bc8b27404326eb51910b72ded60a3ce670e0623d0d138496f74b4ade86142000000000000000fda782771428e91cb2c31672933cd13ef3ccd85c5554e8d4da365e5ebb5c570820000000000000002bf5c27c51e6d9bfda8c83578f8b2aaaf5e796b0c9943b1571b41ccc3a70122f2000000000000000f67a71be9973395b73175c6b18c027998f4df58ed1a880316f99b442426e360720000000000000008d3170979947e4ddb9c42ca6d4bc1470ba734f932e7a0a59d3db000bcf038c1a0300000000000000200000000000000061ad66cea975cd142094e82003ac40d282383ca362c005b3a53f7ef4990324222000000000000000f71df9cdfa3ea5706d6ddacc81614adc77c21d4517ef76ad70feab890943792d20000000000000006e802f612f454fbee7dc172cc5841b3e60f6e4f241b0aaab0cbb73b3c176b12720000000000000001919a8d7d260660fb916c6f1f59708a9a463f0a33a9499d8ec7b8c31fc6322050400000000000000200000000000000028470c0ce56ae73a75288368686731d75217d323cced7a3bedde9063ee42e00e20000000000000000ec493e1f6d26c866573689072402f7e8348979c00fba4152fc81cf2d1b8a8112000000000000000c1928e44794d0d63cd122a95c5416ce54c19572878d481e6bb598aa7d975e50420000000000000005814da2375e9d9fad3e04658954389cac3ad0ba5ed6b983baa5cf850dc3fa71820000000000000006b2bb961fb247db55da5e6c109413fa2bbc5dab037f79d6f6b939b65a0d9f81b200000000000000099f44b68e7047cc801bdf168afd8266db0fa33f30f41c3dfea85ef3ae84bf6ae000000002000000000000000233d455eb687dca8b893424414025dec2ca4ecab3667696d8dca7649ee9a241c03000000000000002100000000000000414b1c9581770545413b1e1ebabca73a8e1d34074111903a2a1ab44964fd62888021000000000000007424c9033c95db7de553840e833cf2eb65805dd97e8b2a59f19a2227e81c4fd9002100000000000000237aa365d2aa9340a4bd437fdbdc05924eeb427e360e7a0a7666fae07d415a9400030000000000000020000000000000002d5e896d26a7d6a93376ca849e8b5170a1736e3f2eed7fcc4db5634d5291a6792000000000000000213dfe59994359b29cfe5edfd3a5aad01a4af2c7abd4745ac72557dc3d91a02b2000000000000000ba2fa9834d11ed1693002e828a0412f2316b0017b42f5990007047b6d03a8d712000000000000000ad6af2d9cc6d759afd080a23d3aa506c9db49a6bf21564034e0e38bb8f1c3af12000000000000000315e283d148ebf765c7b95d208377b80c9926a0c27cfc2a7ee82f2c477ee8604200000000000000079b4da505d81ef39c067477f34a88bc7f3802e3d5346eb78c553a6cb58d61f380300000000000000210000000000000032ad0c02c8fcf3cb18521033228a7fbdcfb9225aeeb5693ab9749b4f89e7de22002100000000000000452caface358e8d2c2e8d2a399ff4158c8f7398b3f633a5913a9edb3228b680580210000000000000030d9d7ee2dbd696c0b4303b77eab2096f9140be25f08a85db7b5cc904d0917be00f104000000000000fa0ae7b8b1093a9562294c9ffd54c823be29fe1e33849f7705c7d5d974051b8e80423459563217d556c569ee6bc069c8c5ea4e2ac287ab362816909232fbff690b808ba9b9762e0def1301e41b1d03961c996f6bb9f4e4554e84e8f7d84ff922f2b8800000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000403885f290d084c7011b25bd357147b301515b68e3370953454fa2c7a1ecc832eb80435914d52a6328f60d7491e08b204af87ffbaea46815df48892ed4992e7e006400029604c6e131012907049c304c2c1c00f3cc6bfcdc99c8e3f3acf1ca23077f8280c90bdbc3ab52da57e142d41b0fb7b84495e326dea2f1a973813a251e9efc864a0078a726fda219e6977a6113b9b875f982eb77f4b1ef99e0297d35a37bd4c878ac0003909b3ab70a64e7587d3fd69e8c891594d5235dee807d92b930fed68a70a87220aecb8fbcf8bda1649c443d703c1db4232cef79019245f9433feb6a6b39d23e26c48c8704a1f32c2faedf409073e484460134c50dd85cf54f33e355b335b0320b00000000000000a5417394088682b98382f499678f256930b9e505ae71f0025d1b8a9725af605a8050c6af7a4a01582e552c172a3444b3ef7a28e39f6dd83df7a75b473b3ebe8011808599e04b82c720ecc903962d5f118732afd3b4a0accc59d5939a9c2b3736017f00f73531bb3351de172bd08fd4c2501074104c9de55bfc9612e836eb82b9c4dd4000dd207187c9e7b42732b3cc3dc191339264b78e186bde252d23d464d552edd63780d3e3a070a70a784e8d5f6645ae16a1c5fa89c06abfac6f8de7514bb5cdd2968000f4be71e06c2e2a3796b87fbabc76669b64cb7bd1ad448be39edf117fe04565ab0047d8c79e02476f7496fbb03c94c403650e996da986f901ba7eb30d28eaf38281005ce62f06e717936e1db74bd580b2df04b02699bf374a11ccbbf21f15e00f21da00877bfefa47b28f3a88a1e410e8bd355ff6522148a7387ccc91a84a99c1c125610021ff5c252d2ae321af66a6dc5daa6bc883707da47e931055dec0b83f5917c5d1000b00000000000000c4ca6305544100f68be9e6eb02056e45ecf1da7e1cad6f9c2e1bd54a51b12b900058c6665bf2f317e18ce27a056b82880b340df1f6bb4b89fa6eaccd4c1f91c0c3008bb0c5e5391b69e19891a8d42d0edaab3468aedf911a07605aa3182f55b869c4803e3b98348a3bb399e13d8635756c5bd35d6ed8488e35d1947d51a86c5a5c88830035f11282868ac25b18e2b38942b576dc7f6dc02df4918ecd5fd77b1a8f58dc33803645c0345347aa0ab8831f93a14f346a3d105bf4155c00c0859e0976a51fd8c580ddecafe6b2ca0ccbff84e16081f09b0814b99705f75c8d9ca864e054a859aab700ec24a84c02c528a527e4b18a5e30bc48d50f5e9de3be63dc3135a9abae59bb4c00c1f4858879a10a8f641a2b3e2e86165f5e887c0b1c0baa6d9bdccf62e4540494803600035621cf10ab5f1fbee65dea41777f4cbb49e9f88feaa13e2ec01574d7a40022490535ff4029bb18e91cccf226e887996f8f0a8409de306bb170a026d3ae9a00fc293da4c95c495c66dc2a79d03dd4e0b1fa0f86a8fa564e1f5f49960b43d10e804a92bb5f0bcaa7c94fd53a5bc4b47e888807701b9c8e47900b55752818f661000000000000000000000000000000000000000000").unwrap();

        let _res = Transfer::new(&encode);
        //println!("{:?}", res.err());
    }
}
