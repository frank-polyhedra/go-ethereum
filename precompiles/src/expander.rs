use std::{
    fs::File,
    io::{Cursor, Write},
    path::Path,
    slice,
};

use alloy::sol_types::{sol_data::Bytes, SolType};
use arith::{Field, FieldSerde};
use expander_rs::{
    BN254ConfigSha2, Circuit, Config, FieldType, GKRConfig, GKRScheme, M31ExtConfigSha2, Proof,
    Verifier, SENTINEL_BN254, SENTINEL_M31,
};
use tempfile::TempDir;

pub enum Error {
    AbiDecodeError,
    TempDirError,
    OpenFileError,
    WriteDataError,
    ConvertFieldError,
    UnknownFieldError,
}

impl From<Error> for u8 {
    fn from(value: Error) -> Self {
        match value {
            Error::AbiDecodeError => 1,
            Error::TempDirError => 2,
            Error::OpenFileError => 3,
            Error::WriteDataError => 4,
            Error::ConvertFieldError => 5,
            Error::UnknownFieldError => 6,
        }
    }
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn __precompile_expander_verify(
    data_ptr: *const u8,
    data_len: usize,
    ret_val: *mut u8,
) -> u8 {
    let data = unsafe { slice::from_raw_parts(data_ptr, data_len) };
    let ret = unsafe { slice::from_raw_parts_mut(ret_val, 32) };

    match verify(data) {
        Ok(res) => {
            ret.copy_from_slice(&res);
            println!("{:?}", res);
            0
        }
        Err(e) => e.into(),
    }
}

fn write_data(path: &Path, data: &[u8]) -> Result<(), Error> {
    let mut file = File::create(path).map_err(|_| Error::OpenFileError)?;
    file.write_all(data).map_err(|_| Error::WriteDataError)?;
    Ok(())
}

fn verify(data: &[u8]) -> Result<[u8; 32], Error> {
    let tmp_dir = TempDir::new().map_err(|_| Error::TempDirError)?;

    let dir_path = tmp_dir.path();

    let (proof_bytes, witness_bytes) =
        <(Bytes, Bytes)>::abi_decode_params(data, true).map_err(|_| Error::AbiDecodeError)?;

    let circuit_bytes = include_bytes!("../assets/circuit.txt");

    write_data(&dir_path.join("proof.txt"), &proof_bytes)?;
    write_data(&dir_path.join("witness.txt"), &witness_bytes)?;
    write_data(&dir_path.join("circuit.txt"), circuit_bytes)?;

    let proof = format!("{}", dir_path.join("proof.txt").display());
    let witness = format!("{}", dir_path.join("witness.txt").display());
    let circuit = format!("{}", dir_path.join("circuit.txt").display());

    run_expander_verify(&proof, &proof_bytes, &witness, &circuit, circuit_bytes)?;

    let res = [0xffu8; 32];

    Ok(res)
}

fn run_expander_verify(
    proof: &str,
    proof_bytes: &[u8],
    witness: &str,
    circuit: &str,
    circuit_bytes: &[u8],
) -> Result<bool, Error> {
    println!("{proof}");
    println!("{witness}");
    println!("{circuit}");

    // read last 32 byte of sentinel field element to determine field type
    // let bytes = fs::read(circuit_file).expect("Unable to read circuit file.");
    let field_bytes = &circuit_bytes[8..8 + 32];
    match field_bytes
        .try_into()
        .map_err(|_| Error::ConvertFieldError)?
    {
        SENTINEL_M31 => run_command(
            circuit,
            Config::<M31ExtConfigSha2>::new(GKRScheme::Vanilla),
            witness,
            proof_bytes,
        ),
        SENTINEL_BN254 => run_command(
            circuit,
            Config::<BN254ConfigSha2>::new(GKRScheme::Vanilla),
            witness,
            proof_bytes,
        ),
        _ => Err(Error::UnknownFieldError),
    }
}

fn run_command<C: GKRConfig>(
    circuit_file: &str,
    config: Config<C>,
    witness: &str,
    proof_bytes: &[u8],
) -> Result<bool, Error> {
    let mut circuit = Circuit::<C>::load_circuit(circuit_file);
    circuit.load_witness_file(witness);

    let (proof, claimed_v) = load_proof_and_claimed_v(&proof_bytes);
    let verifier = Verifier::new(&config);

    Ok(verifier.verify(&mut circuit, &claimed_v, &proof))
}

fn load_proof_and_claimed_v<F: Field + FieldSerde>(bytes: &[u8]) -> (Proof, F) {
    let mut cursor = Cursor::new(bytes);

    let proof = Proof::deserialize_from(&mut cursor).unwrap(); // TODO: error propagation
    let claimed_v = F::deserialize_from(&mut cursor).unwrap(); // TODO: error propagation

    (proof, claimed_v)
}
