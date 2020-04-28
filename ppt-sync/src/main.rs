use std::sync::Arc;
use tokio::prelude::*;
use tokio::net::TcpListener;
use tokio::sync::{ Barrier, Notify };
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

#[tokio::main]
async fn main() -> Result<()> {
    let barrier = Arc::new(Barrier::new(2));
    let notifier = Arc::new(Notify::new());

    let mut listener = TcpListener::bind("127.0.0.1:57236").await?;
    println!();
    let mut connections = vec![];
    connections.push((listener.accept().await?.0, true));

    let b = barrier.clone();
    let n = notifier.clone();
    let mut ppt = tokio::task::spawn_blocking(move || {
        let mut runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            unsafe {
                ppt_sync(&b, &n).await;
            }
        });
    });

    while !connections.is_empty() {
        tokio::select! {
            incoming = listener.accept() => {
                let socket = incoming?.0;
                socket.set_nodelay(true)?;
                connections.push((socket, true));
            }
            _ = barrier.wait() => {
                for (socket, status) in &mut connections {
                    *status = socket.write(&[0]).await.is_ok();
                    *status = socket.flush().await.is_ok();
                }
                for (socket, status) in &mut connections {
                    *status = socket.read_exact(&mut [0]).await.is_ok();
                }
                connections.retain(|&(_, status)| status);

                barrier.wait().await;
            }
            _ = &mut ppt => break
        }
    }

    notifier.notify();
    let _ = ppt.await;

    Ok(())
}

fn find_ppt_process() -> Result<Option<u32>> {
    unsafe {
        let mut pids = [0; 4096];
        let mut used = 0;
        if EnumProcesses(
            pids.as_mut_ptr(), std::mem::size_of_val(&pids) as u32, &mut used
        ) == 0 {
            panic!("failed to enumerate processes");
        }

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
                                    return Ok(Some(process))
                                }
                            }
                            break
                        }
                    }
                }

                CloseHandle(handle);
            }
        }
        Ok(None)
    }
}

fn wait_for_event() -> DEBUG_EVENT {
    tokio::task::block_in_place(|| unsafe {
        let mut event = Default::default();
        WaitForDebugEvent(&mut event, INFINITE);
        event
    })
}

async unsafe fn ppt_sync(barrier: &Barrier, notifier: &Notify) {
    let pid;
    loop {
        if let Some(p) = find_ppt_process().unwrap() {
            pid = p;
            break
        }
        tokio::time::delay_for(std::time::Duration::from_secs(1)).await;
    }

    if DebugActiveProcess(pid) == 0 {
        eprintln!("Failed to attach to PPT as a debugger");
        return;
    }

    let event = wait_for_event();
    if event.dwDebugEventCode != CREATE_PROCESS_DEBUG_EVENT {
        panic!("first debug event should have been a CREATE_PROCESS_DEBUG_EVENT");
    }

    let process = event.u.CreateProcessInfo().hProcess;
    let mut tid = event.dwThreadId;
    let mut continue_kind = DBG_EXCEPTION_NOT_HANDLED;

    // this instruction is executed after the call that does window swap buffers
    const INSTRUCTION_ADDRESS: u64 = 0x14025B8CC;

    loop {
        // wait until breakpoint is hit
        if breakpoint(
            pid, &mut tid, &mut continue_kind, process, INSTRUCTION_ADDRESS
        ).is_none() {
            break
        }

        // sync with socket task so it can notify listeners
        tokio::select! {
            _ = barrier.wait() => {}
            _ = notifier.notified() => {
                if ContinueDebugEvent(pid, tid, continue_kind) == 0 { panic!(); }
                break
            }
        }
        // sync with socket task so we know the listeners have responded
        tokio::select! {
            _ = barrier.wait() => {}
            _ = notifier.notified() => {
                if ContinueDebugEvent(pid, tid, continue_kind) == 0 { panic!(); }
                break
            }
        }

        // go past breakpointed instruction
        if step(pid, &mut tid, &mut continue_kind).is_none() {
            break
        }
    }

    DebugActiveProcessStop(pid);
}

unsafe fn breakpoint(
    pid: u32, tid: &mut u32, continue_kind: &mut u32, process: HANDLE, address: u64
) -> Option<()> {
    let mut original = 0u8;
    let mut rw = 0;
    if ReadProcessMemory(
        process, address as *mut _, &mut original as *mut _ as *mut _, 1, &mut rw
    ) == 0 {
        panic!("read failed");
    }

    if WriteProcessMemory(
        process, address as *mut _, &0xCC as *const _ as *const _, 1, &mut rw
    ) == 0 {
        panic!("write breakpoint failed");
    }

    loop {
        if ContinueDebugEvent(pid, *tid, *continue_kind) == 0 { panic!(); }
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

        if WriteProcessMemory(
            process, address as *mut _, &original as *const _ as *const _, 1, &mut rw
        ) == 0 {
            panic!("writeback failed");
        }

        let thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, 0, *tid);
        let mut regs = CONTEXT::default();
        regs.ContextFlags = CONTEXT_ALL;
        if GetThreadContext(thread, &mut regs) == 0 {
            panic!("GetThreadContext failed: {}", GetLastError());
        }
        regs.Rip = address;
        if SetThreadContext(thread, &regs) == 0 {
            panic!("SetThreadContext failed: {}", GetLastError());
        }
        *continue_kind = DBG_CONTINUE;
        CloseHandle(thread);
        return Some(());
    }
}

unsafe fn step(pid: u32, tid: &mut u32, continue_kind: &mut u32) -> Option<()> {
    let thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, 0, *tid);
    let mut regs = CONTEXT::default();
    regs.ContextFlags = CONTEXT_ALL;
    if GetThreadContext(thread, &mut regs) == 0 {
        panic!("GetThreadContext failed: {}", GetLastError());
    }
    regs.EFlags |= 0x100;
    if SetThreadContext(thread, &regs) == 0 {
        panic!("SetThreadContext failed: {}", GetLastError());
    }
    CloseHandle(thread);

    loop {
        if ContinueDebugEvent(pid, *tid, *continue_kind) == 0 { panic!(); }
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