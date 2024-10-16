use crate::{utils, Error, Result};
use ethabi::ParamType;
use hypr_api::{
    algebra::{bn254::BN254Scalar, prelude::*},
    crypto::anemoi_jive::{AnemoiJive, AnemoiJive254, ANEMOI_JIVE_BN254_SALTS},
};

use core::slice;
use num_bigint::BigUint;

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn __precompile_anemoi(
    data_ptr: *const u8,
    data_len: usize,
    ret_val: *mut u8,
) -> u8 {
    let data = unsafe { slice::from_raw_parts(data_ptr, data_len) };
    let ret = unsafe { slice::from_raw_parts_mut(ret_val, 32) };

    match compute(data, ret) {
        Ok(()) => 0,
        Err(e) => e.code(),
    }
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn __precompile_anemoi_gas(data_ptr: *const u8, data_len: usize) -> u64 {
    let data = unsafe { slice::from_raw_parts(data_ptr, data_len) };

    gas(data).unwrap_or_default()
}

fn eval_jive4(data: &[u8], ret: &mut [u8]) -> Result<()> {
    let param = ParamType::FixedBytes(32);

    let r = ethabi::decode(&[param.clone(), param.clone(), param.clone(), param], data)
        .map_err(|_| Error::ParseDataFailed)?;

    let x0 = utils::into_bytes32(r.get(0).cloned()).ok_or(Error::ParseDataFailed)?;
    let x1 = utils::into_bytes32(r.get(1).cloned()).ok_or(Error::ParseDataFailed)?;
    let y0 = utils::into_bytes32(r.get(2).cloned()).ok_or(Error::ParseDataFailed)?;
    let y1 = utils::into_bytes32(r.get(3).cloned()).ok_or(Error::ParseDataFailed)?;

    let res = AnemoiJive254::eval_jive(
        &[
            BN254Scalar::from_bytes(&x0).map_err(|_| Error::ParseDataFailed)?,
            BN254Scalar::from_bytes(&x1).map_err(|_| Error::ParseDataFailed)?,
        ],
        &[
            BN254Scalar::from_bytes(&y0).map_err(|_| Error::ParseDataFailed)?,
            BN254Scalar::from_bytes(&y1).map_err(|_| Error::ParseDataFailed)?,
        ],
    );

    ret.copy_from_slice(&res.to_bytes());

    Ok(())
}

fn eval_variable_length_hash(data: &[u8], ret: &mut [u8]) -> Result<()> {
    let param = ParamType::FixedBytes(32);
    let uid_param = ParamType::Uint(64);

    let r = ethabi::decode(&[uid_param, param], data).map_err(|_| Error::ParseDataFailed)?;

    let h0 = utils::into_uint(r.get(0).cloned()).ok_or(Error::ParseDataFailed)? as u64;
    let h1 = utils::into_bytes32(r.get(1).cloned()).ok_or(Error::ParseDataFailed)?;

    let res = AnemoiJive254::eval_variable_length_hash(&[
        BN254Scalar::from(h0),
        BN254Scalar::from_bytes(&h1).map_err(|_| Error::ParseDataFailed)?,
    ]);

    ret.copy_from_slice(&res.to_bytes());

    Ok(())
}

fn jive_254_salts(data: &[u8], ret: &mut [u8]) -> Result<()> {
    let r = ethabi::decode(&[ParamType::Uint(128)], data).map_err(|_| Error::ParseDataFailed)?;

    let index = utils::into_uint(r.get(0).cloned()).ok_or(Error::ParseDataFailed)?;

    if index < 64 {
        let point = BigUint::from(ANEMOI_JIVE_BN254_SALTS[index as usize]).to_bytes_le();

        ret.copy_from_slice(&point);
        Ok(())
    } else {
        Err(Error::InputOutOfBound)
    }
}

// anemoi_jive_4(bytes32,bytes32,bytes32,bytes32) 0x73808263
pub const ANEMOI_JIVE_4_SELECTOR: [u8; 4] = [0x73, 0x80, 0x82, 0x63];
// anemoi_jive_254_salts(uint128) 0x51dec097
pub const ANEMOI_JIVE_254_SALTS_SELECTOR: [u8; 4] = [0x51, 0xde, 0xc0, 0x97];
// anemoi_variable_length_hash(uint64, bytes32) 0x47f3b098
pub const ANEMO_EVAL_V_LENGTH: [u8; 4] = [0x47, 0xf3, 0xb0, 0x98];

pub fn compute(data: &[u8], ret: &mut [u8]) -> Result<()> {
    if data.len() < 4 {
        return Err(Error::WrongSelectorLength);
    }

    match [data[0], data[1], data[2], data[3]] {
        ANEMOI_JIVE_4_SELECTOR => eval_jive4(&data[4..], ret)?,
        ANEMOI_JIVE_254_SALTS_SELECTOR => jive_254_salts(&data[4..], ret)?,
        ANEMO_EVAL_V_LENGTH => eval_variable_length_hash(&data[4..], ret)?,
        _ => return Err(Error::UnknownSelector),
    }

    Ok(())
}

pub const ANEMOI_SALT_GAS: u64 = 10;
pub const ANEMOI_EVAL_4: u64 = 400;

pub fn gas(data: &[u8]) -> Result<u64> {
    if data.len() < 4 {
        return Err(Error::WrongSelectorLength);
    }

    match [data[0], data[1], data[2], data[3]] {
        ANEMOI_JIVE_4_SELECTOR => Ok(ANEMOI_SALT_GAS),
        ANEMOI_JIVE_254_SALTS_SELECTOR => Ok(ANEMOI_EVAL_4),
        _ => Err(Error::UnknownSelector),
    }
}
