#![windows_subsystem = "windows"]
use std::sync::mpsc::{ Sender, Receiver, channel };
use named_pipe::{ PipeOptions };
use std::io::prelude::*;
use winapi::um::psapi::{ EnumProcesses, EnumProcessModules, GetModuleBaseNameW };
use winapi::um::processthreadsapi::{ OpenProcess, OpenThread, GetThreadContext, SetThreadContext };
use winapi::um::winnt::*;
use winapi::um::handleapi::CloseHandle;
use winapi::um::memoryapi::{ ReadProcessMemory, WriteProcessMemory };
use winapi::um::winbase::*;
use winapi::um::minwinbase::*;
use winapi::um::debugapi::*;
use winapi::um::errhandlingapi::GetLastError;
use std::os::windows::ffi::OsStringExt;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() -> Result<()> {
    let mut listener = PipeOptions::new("\\\\.\\pipe\\ppt-sync").single()?;
    println!();

    let (done, waiter) = channel();
    let (notifs, conns) = channel();

    std::thread::spawn(move || { let _: Result<()> = (|| loop {
        let mut connection = listener.wait()?;
        listener = PipeOptions::new("\\\\.\\pipe\\ppt-sync").first(false).single()?;
        let (notifier, wait) = channel();
        notifs.send(notifier)?;
        let done = done.clone();
        std::thread::spawn(move || { let _: Result<_> = (|| loop {
            wait.recv()?;
            let good = (|| {
                connection.write(&[0])?;
                connection.flush()?;
                connection.read_exact(&mut [0])
            })().is_ok();
            if !good {
                drop(wait);
                done.send(())?;
                return Ok(())
            }
            done.send(())?;
        })();});
    })();});

    unsafe {
        ppt_sync(waiter, conns);
    }

    Ok(())
}

macro_rules! w {
    ($f:ident($($content:tt)*)) => {
        match $f($($content)*) {
            0 => {
                eprintln!(
                    "{} (line {}) failed with error code {}",
                    stringify!(f), line!(), GetLastError()
                );
                None
            }
            v => Some(v)
        }
    };
}

fn find_ppt_process() -> Option<u32> {
    unsafe {
        let mut pids = [0; 4096];
        let mut used = 0;
        w!(EnumProcesses(
            pids.as_mut_ptr(), std::mem::size_of_val(&pids) as u32, &mut used
        )).unwrap();

        for &process in &pids[..used as usize/std::mem::size_of::<u32>()] {
            let handle = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, process
            );
            if !handle.is_null() {
                let mut module = 0 as *mut _;
                if EnumProcessModules(
                    handle,
                    &mut module,
                    std::mem::size_of::<*mut ()>() as u32,
                    &mut used
                ) != 0 {
                    let mut buffer = vec![0; 4096];
                    GetModuleBaseNameW(
                        handle, module, buffer.as_mut_ptr(), 2*buffer.len() as u32
                    );
                    for i in 0..buffer.len() {
                        if buffer[i] == 0 {
                            let s = std::ffi::OsString::from_wide(&buffer[..i]);
                            if let Some(s) = s.to_str() {
                                if s == "puyopuyotetris.exe" {
                                    CloseHandle(handle);
                                    return Some(process)
                                }
                            }
                            break
                        }
                    }
                }

                CloseHandle(handle);
            }
        }
        None
    }
}

unsafe fn wait_for_event() -> DEBUG_EVENT {
    let mut event = Default::default();
    WaitForDebugEvent(&mut event, INFINITE);
    event
}

unsafe fn ppt_sync(waiter: Receiver<()>, new: Receiver<Sender<()>>) {
    let pid;
    loop {
        if let Some(p) = find_ppt_process() {
            pid = p;
            break
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    if w!(DebugActiveProcess(pid)).is_none() {
        return
    }

    let event = wait_for_event();
    if event.dwDebugEventCode != CREATE_PROCESS_DEBUG_EVENT {
        eprintln!("first debug event should have been a CREATE_PROCESS_DEBUG_EVENT");
        w!(DebugActiveProcessStop(pid));
        return;
    }

    let process = event.u.CreateProcessInfo().hProcess;
    let mut tid = event.dwThreadId;
    let mut continue_kind = DBG_EXCEPTION_NOT_HANDLED;

    // this instruction is executed after the call that does window swap buffers
    const INSTRUCTION_ADDRESS: u64 = 0x14025B8CC;

    let mut clients = vec![];
    if let Ok(c) = new.recv(){
        clients.push(c);
    }

    loop {
        // wait until breakpoint is hit
        if breakpoint(
            pid, &mut tid, &mut continue_kind, process, INSTRUCTION_ADDRESS
        ).is_none() {
            break
        }

        // collect new clients
        for c in new.try_iter() {
            clients.push(c);
        }
        // notify clients
        clients.retain(|c| c.send(()).is_ok());

        // wait for clients to respond
        for _ in 0..clients.len() {
            waiter.recv().ok();
        }

        if clients.is_empty() {
            w!(ContinueDebugEvent(pid, tid, continue_kind));
            break
        }

        // go past breakpointed instruction
        if step(pid, &mut tid, &mut continue_kind).is_none() {
            break
        }
    }

    w!(DebugActiveProcessStop(pid));
}

unsafe fn breakpoint(
    pid: u32, tid: &mut u32, continue_kind: &mut u32, process: HANDLE, address: u64
) -> Option<()> {
    let mut original = 0u8;
    let mut rw = 0;
    w!(ReadProcessMemory(
        process, address as *mut _, &mut original as *mut _ as *mut _, 1, &mut rw
    ))?;

    w!(WriteProcessMemory(
        process, address as *mut _, &0xCC as *const _ as *const _, 1, &mut rw
    ))?;

    loop {
        w!(ContinueDebugEvent(pid, *tid, *continue_kind))?;
        let event = wait_for_event();
        *tid = event.dwThreadId;
        if event.dwDebugEventCode != EXCEPTION_DEBUG_EVENT {
            if event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT {
                return None
            }
            *continue_kind = DBG_EXCEPTION_NOT_HANDLED;
            continue;
        }

        let info = &event.u.Exception().ExceptionRecord;
        if info.ExceptionCode != EXCEPTION_BREAKPOINT {
            *continue_kind = DBG_EXCEPTION_NOT_HANDLED;
            continue;
        }
        if info.ExceptionAddress as u64 != address {
            *continue_kind = DBG_EXCEPTION_NOT_HANDLED;
            continue;
        }

        w!(WriteProcessMemory(
            process, address as *mut _, &original as *const _ as *const _, 1, &mut rw
        ))?;

        let thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, 0, *tid);
        let mut regs = CONTEXT::default();
        regs.ContextFlags = CONTEXT_ALL;
        w!(GetThreadContext(thread, &mut regs))?;
        regs.Rip = address;
        w!(SetThreadContext(thread, &regs))?;
        *continue_kind = DBG_CONTINUE;
        w!(CloseHandle(thread))?;
        return Some(());
    }
}

unsafe fn step(pid: u32, tid: &mut u32, continue_kind: &mut u32) -> Option<()> {
    let thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, 0, *tid);
    let mut regs = CONTEXT::default();
    regs.ContextFlags = CONTEXT_ALL;
    w!(GetThreadContext(thread, &mut regs))?;
    regs.EFlags |= 0x100;
    w!(SetThreadContext(thread, &regs))?;
    CloseHandle(thread);

    loop {
        w!(ContinueDebugEvent(pid, *tid, *continue_kind))?;
        let event = wait_for_event();
        *tid = event.dwThreadId;
        if event.dwDebugEventCode != EXCEPTION_DEBUG_EVENT {
            if event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT {
                return None
            }
            *continue_kind = DBG_EXCEPTION_NOT_HANDLED;
            continue;
        }

        let info = &event.u.Exception().ExceptionRecord;
        if info.ExceptionCode != EXCEPTION_SINGLE_STEP {
            *continue_kind = DBG_EXCEPTION_NOT_HANDLED;
            continue;
        }
        *continue_kind = DBG_CONTINUE;

        return Some(());
    }
}