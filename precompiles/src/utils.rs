use alloc::vec::Vec;
use ethabi::{Address, Token};
use hypr_api::{
    anon_xfr::AXfrAddressFoldingInstance,
    parameters::AddressFormat,
    structs::{AssetType, ASSET_TYPE_LENGTH},
};
use primitive_types::U256;

use crate::{Error, Result};

#[allow(unused)]
pub fn into_bytes32(tk: Option<Token>) -> Option<[u8; 32]> {
    tk.and_then(|v| v.into_fixed_bytes())
        .and_then(|v| v.try_into().ok())
}

#[allow(unused)]
pub fn into_bytes32_array(tk: Option<Token>) -> Option<Vec<[u8; 32]>> {
    let tokens = tk.and_then(|v| v.into_array())?;

    let mut res = Vec::with_capacity(tokens.len());
    for token in tokens {
        let bytes32 = into_bytes32(Some(token))?;
        res.push(bytes32)
    }

    Some(res)
}

#[allow(unused)]
pub fn into_address(tk: Option<Token>) -> Option<Address> {
    tk.and_then(|v| v.into_address())
}

#[allow(unused)]
pub fn into_uint256(tk: Option<Token>) -> Option<U256> {
    tk.and_then(|v| v.into_uint())
}

#[allow(unused)]
pub fn into_uint(tk: Option<Token>) -> Option<u128> {
    into_uint256(tk).map(|v| v.as_u128())
}

#[allow(unused)]
pub fn into_uint_array(tk: Option<Token>) -> Option<Vec<u128>> {
    let tokens = tk.and_then(|v| v.into_array())?;

    let mut res = Vec::with_capacity(tokens.len());
    for token in tokens {
        let uint = into_uint(Some(token))?;
        res.push(uint)
    }

    Some(res)
}

#[allow(unused)]
pub fn into_uint256_array(tk: Option<Token>) -> Option<Vec<U256>> {
    let tokens = tk.and_then(|v| v.into_array())?;

    let mut res = Vec::with_capacity(tokens.len());
    for token in tokens {
        let uint = into_uint256(Some(token))?;
        res.push(uint)
    }

    Some(res)
}

#[allow(unused)]
pub fn into_bytes(tk: Option<Token>) -> Option<Vec<u8>> {
    tk.and_then(|v| v.into_bytes())
}

#[allow(unused)]
pub fn into_bytes_array(tk: Option<Token>) -> Option<Vec<Vec<u8>>> {
    let tokens = tk.and_then(|v| v.into_array())?;

    let mut res = Vec::with_capacity(tokens.len());
    for token in tokens {
        let bytes = into_bytes(Some(token))?;
        res.push(bytes)
    }

    Some(res)
}

pub fn join_bytes32(byte32s: &[[u8; 32]]) -> Vec<u8> {
    let mut v = Vec::with_capacity(byte32s.len() * 32);

    for b in byte32s {
        v.extend_from_slice(b);
    }

    v
}

pub fn split_bytes32(bytes32: &Vec<u8>) -> Result<Vec<&[u8; 32]>> {
    let num = bytes32.len() / 32;

    let mut res = Vec::with_capacity(num);

    for i in 0..num {
        let begin = i * 32;
        let end = (i + 1) * 32;

        let b32 = bytes32.get(begin..end).ok_or(Error::ParseDataFailed)?;

        res.push(b32.try_into().map_err(|_| Error::ParseDataFailed)?)
    }

    Ok(res)
}

pub fn bytes_asset(bytes: &[u8]) -> Result<AssetType> {
    if bytes.len() != ASSET_TYPE_LENGTH {
        return Err(Error::ParseDataFailed);
    }
    let mut asset_bytes = [0u8; ASSET_TYPE_LENGTH];
    asset_bytes.copy_from_slice(bytes);
    Ok(AssetType(asset_bytes))
}

pub fn check_address_format_from_folding(folding: &AXfrAddressFoldingInstance) -> AddressFormat {
    match folding {
        AXfrAddressFoldingInstance::Ed25519(_) => AddressFormat::ED25519,
        AXfrAddressFoldingInstance::Secp256k1(_) => AddressFormat::SECP256K1,
    }
}
