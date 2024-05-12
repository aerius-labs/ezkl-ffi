extern crate libc;

mod util;

#[no_mangle]
pub extern "C" fn verify(
    proof_length: libc::size_t,
    proof: *const u8,
    vk_length: libc::size_t,
    vk: *const u8,
    settings_length: libc::size_t,
    settings: *const u8,
    srs_length: libc::size_t,
    srs: *const u8,
) -> libc::__u8 {
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

    result as u8
}