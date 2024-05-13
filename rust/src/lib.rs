#![allow(clippy::not_unsafe_ptr_arg_deref)]
extern crate libc;

mod util;
use std::{
    ffi::CString
};
use std::fs::File;
use std::io::Write;

#[no_mangle]
pub extern "C" fn verify_proof(
    proof_length: libc::size_t,
    proof: *const u8,
    vk_length: libc::size_t,
    vk: *const u8,
    settings_length: libc::size_t,
    settings: *const u8,
    srs_length: libc::size_t,
    srs: *const u8,
) -> bool {
    // convert all const u8 to Vec<u8>
    let proof_slice =
        unsafe { std::slice::from_raw_parts(proof as *const u8, proof_length) };
    let proof_vec = proof_slice.to_vec();

    let vk_slice = unsafe { std::slice::from_raw_parts(vk as *const u8, vk_length) };
    let vk_vec = vk_slice.to_vec();

    let settings_slice = unsafe { std::slice::from_raw_parts(settings as *const u8, settings_length) };
    let settings_vec = settings_slice.to_vec();

    let srs_slice = unsafe { std::slice::from_raw_parts(srs as *const u8, srs_length) };
    let srs_vec = srs_slice.to_vec();

    // call the verify function from util.rs
    let result = util::verify(proof_vec, vk_vec, settings_vec, srs_vec).unwrap();

    result
}

#[no_mangle]
pub extern "C" fn prove(
    witness_length: libc::size_t,
    witness: *const u8,
    pk_length: libc::size_t,
    pk: *const u8,
    cpmpiled_circuit_length: libc::size_t,
    compiled_circuit: *const u8,
    srs_length: libc::size_t,
    srs: *const u8,
) -> *const libc::c_char {
    // convert all const u8 to Vec<u8>
    let witness_slice =
        unsafe { std::slice::from_raw_parts(witness as *const u8, witness_length) };
    let witness_vec = witness_slice.to_vec();

    let pk_slice = unsafe { std::slice::from_raw_parts(pk as *const u8, pk_length) };
    let pk_vec = pk_slice.to_vec();

    let compiled_circuit_slice = unsafe { std::slice::from_raw_parts(compiled_circuit as *const u8, cpmpiled_circuit_length) };
    let compiled_circuit_vec = compiled_circuit_slice.to_vec();

    let srs_slice = unsafe { std::slice::from_raw_parts(srs as *const u8, srs_length) };
    let srs_vec = srs_slice.to_vec();

    // call the prove function from util.rs
    let result = util::prove(witness_vec, pk_vec, compiled_circuit_vec, srs_vec).unwrap();

    CString::new(result).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn gen_vk(
    compiled_circuit_length: libc::size_t,
    compiled_circuit: *const u8,
    params_serialized_length: libc::size_t,
    params_serialized: *const u8,
    compress_selectors: bool,
) {
    let compiled_circuit_slice = unsafe { std::slice::from_raw_parts(compiled_circuit as *const u8, compiled_circuit_length) };
    let compiled_circuit_vec = compiled_circuit_slice.to_vec();

    let params_serialized_slice = unsafe { std::slice::from_raw_parts(params_serialized as *const u8, params_serialized_length) };
    let params_serialized_vec = params_serialized_slice.to_vec();

    println!("generating vk");
    // call the gen_vk function from util.rs
    let result = util::gen_vk(compiled_circuit_vec, params_serialized_vec, compress_selectors).unwrap();
    // output result vector to file, using rust fs
    let mut file = File::create("./vk.key").unwrap();
    file.write_all(&result).unwrap();
}
#[no_mangle]
pub extern "C" fn gen_pk(
    vk_length: libc::size_t,
    vk: *const u8,
    circuit_length: libc::size_t,
    circuit: *const u8,
    params_serialized_length: libc::size_t,
    params_serialized: *const u8,
) {
    let vk_slice = unsafe { std::slice::from_raw_parts(vk as *const u8, vk_length) };
    let vk_vec = vk_slice.to_vec();

    let circuit_slice = unsafe { std::slice::from_raw_parts(circuit as *const u8, circuit_length) };
    let circuit_vec = circuit_slice.to_vec();

    let params_serialized_slice = unsafe { std::slice::from_raw_parts(params_serialized as *const u8, params_serialized_length) };
    let params_serialized_vec = params_serialized_slice.to_vec();

    println!("generating pk");
    // call the gen_pk function from util.rs
    let result = util::gen_pk(vk_vec, circuit_vec, params_serialized_vec).unwrap();
    // output result vector to file, using rust fs
    let mut file = File::create("./pk.key").unwrap();
    file.write_all(&result).unwrap();
}