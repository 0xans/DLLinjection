extern crate winapi;

use std::{
    ffi::CString,
    ptr::null_mut as NULL,
};
use winapi::{
    shared::minwindef::{
        HINSTANCE,
        DWORD,
        LPVOID
    },
    um::{
        winuser::{
            MessageBoxA, 
            MB_OK, 
            MB_HELP
        },
        libloaderapi::DisableThreadLibraryCalls,
        winnt::DLL_PROCESS_ATTACH,
    },
};

#[no_mangle]
pub extern "system" fn DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, _lpvReserved: LPVOID) -> i32 {
    match fdwReason {
        DLL_PROCESS_ATTACH => {
            if let Err(e) = process_attach(hinstDLL) {
                eprintln!("Error: {:?}", e);
            }
        }
        _ => {}
    }
    1
}

fn process_attach(hinstDLL: HINSTANCE) -> Result<(), Box<dyn std::error::Error>> {
    unsafe { DisableThreadLibraryCalls(hinstDLL) };

    let body = CString::new("UwU")?;
    let title = CString::new("DLL injection message!")?;

    unsafe {
        MessageBoxA(
            NULL(),
            body.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_HELP,
        );
    }

    Ok(())
}
