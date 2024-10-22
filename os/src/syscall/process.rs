//! Process management syscalls
use alloc::sync::Arc;

use crate::{
    config::{BIG_STRIDE,MAX_SYSCALL_NUM},
    loader::get_app_data_by_name,
    mm::{
        range_is_mapped, range_is_unmapped, translated_byte_buffer, translated_refmut,
        translated_str,
    },
    task::{
        add_task, current_task, current_user_token, exit_current_and_run_next,
        free_current_task_frame, insert_current_task_frame, suspend_current_and_run_next,
        TaskStatus,
    },
    timer::get_time_us,
};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// Task information
#[allow(dead_code)]
pub struct TaskInfo {
    /// Task status in it's life cycle
    status: TaskStatus,
    /// The numbers of syscall called by task
    syscall_times: [u32; MAX_SYSCALL_NUM],
    /// Total running time of task
    time: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(exit_code: i32) -> ! {
    trace!("kernel:pid[{}] sys_exit", current_task().unwrap().pid.0);
    exit_current_and_run_next(exit_code);
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel:pid[{}] sys_yield", current_task().unwrap().pid.0);
    suspend_current_and_run_next();
    0
}

pub fn sys_getpid() -> isize {
    trace!("kernel: sys_getpid pid:{}", current_task().unwrap().pid.0);
    current_task().unwrap().pid.0 as isize
}

pub fn sys_fork() -> isize {
    trace!("kernel:pid[{}] sys_fork", current_task().unwrap().pid.0);
    let current_task = current_task().unwrap();
    let new_task = current_task.fork();
    let new_pid = new_task.pid.0;
    // modify trap context of new_task, because it returns immediately after switching
    let trap_cx = new_task.inner_exclusive_access().get_trap_cx();
    // we do not have to move to next instruction since we have done it before
    // for child process, fork returns 0
    trap_cx.x[10] = 0;
    // add new task to scheduler
    add_task(new_task);
    new_pid as isize
}

pub fn sys_exec(path: *const u8) -> isize {
    trace!("kernel:pid[{}] sys_exec", current_task().unwrap().pid.0);
    let token = current_user_token();
    let path = translated_str(token, path);
    if let Some(data) = get_app_data_by_name(path.as_str()) {
        let task = current_task().unwrap();
        task.exec(data);
        0
    } else {
        -1
    }
}

/// If there is not a child process whose pid is same as given, return -1.
/// Else if there is a child process but it is still running, return -2.
pub fn sys_waitpid(pid: isize, exit_code_ptr: *mut i32) -> isize {
    trace!(
        "kernel::pid[{}] sys_waitpid [{}]",
        current_task().unwrap().pid.0,
        pid
    );
    let task = current_task().unwrap();
    // find a child process

    // ---- access current PCB exclusively
    let mut inner = task.inner_exclusive_access();
    if !inner
        .children
        .iter()
        .any(|p| pid == -1 || pid as usize == p.getpid())
    {
        return -1;
        // ---- release current PCB
    }
    let pair = inner.children.iter().enumerate().find(|(_, p)| {
        // ++++ temporarily access child PCB exclusively
        p.inner_exclusive_access().is_zombie() && (pid == -1 || pid as usize == p.getpid())
        // ++++ release child PCB
    });
    if let Some((idx, _)) = pair {
        let child = inner.children.remove(idx);
        // confirm that child will be deallocated after being removed from children list
        assert_eq!(Arc::strong_count(&child), 1);
        let found_pid = child.getpid();
        // ++++ temporarily access child PCB exclusively
        let exit_code = child.inner_exclusive_access().exit_code;
        // ++++ release child PCB
        *translated_refmut(inner.memory_set.token(), exit_code_ptr) = exit_code;
        found_pid as isize
    } else {
        -2
    }
    // ---- release current PCB automatically
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(_ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel:pid[{}] sys_get_time", current_task().unwrap().pid.0);
    // 获取当前进程的页表 token
    let token = current_user_token();
    // 将用户传入的指针 ts 转换为内核可以访问的字节缓冲区
    let byte_slices =
        translated_byte_buffer(token, _ts as *const u8, core::mem::size_of::<TimeVal>());
    // 获取当前的时间（假设返回的时间是以微秒为单位的 us）
    let us = get_time_us();
    // 创建一个 TimeVal 实例，包含秒数和微秒数
    let time_val = TimeVal {
        sec: us / 1_000_000,
        usec: us % 1_000_000,
    };
    // 将 time_val 转换为字节数组
    let time_val_bytes = unsafe {
        core::slice::from_raw_parts(
            &time_val as *const TimeVal as *const u8,
            core::mem::size_of::<TimeVal>(),
        )
    };
    // 使用 assert! 确保字节切片的总大小等于 TimeVal 的大小
    assert!(
        byte_slices.iter().map(|slice| slice.len()).sum::<usize>()
            == core::mem::size_of::<TimeVal>(),
        "Byte slices do not match the size of TimeVal"
    );
    // 把 time_val_bytes 拷贝到 byte_slices 中
    let mut offset = 0;
    for slice in byte_slices {
        let len = slice.len();
        slice.copy_from_slice(&time_val_bytes[offset..offset + len]);
        offset += len;
    }
    0 // 成功返回 0
}

/// YOUR JOB: Finish sys_task_info to pass testcases
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TaskInfo`] is splitted by two pages ?
pub fn sys_task_info(_ti: *mut TaskInfo) -> isize {
    trace!(
        "kernel:pid[{}] sys_task_info",
        current_task().unwrap().pid.0
    );
    let task = current_task().unwrap();
    let inner = task.inner_exclusive_access();

    // 获取当前进程的页表 token
    let token = current_user_token();
    // 将用户传入的指针 _ti 转换为内核可以访问的字节缓冲区
    let byte_slices =
        translated_byte_buffer(token, _ti as *const u8, core::mem::size_of::<TaskInfo>());
    // 创建一个 TaskInfo 实例，填充当前任务的信息
    let task_info = TaskInfo {
        status: inner.task_status,
        syscall_times: inner.task_syscall_times.clone(),
        time: get_time_us() - inner.task_first_be_called_time,
    };
    // 将 task_info 转换为字节数组
    let task_info_bytes = unsafe {
        core::slice::from_raw_parts(
            &task_info as *const TaskInfo as *const u8,
            core::mem::size_of::<TaskInfo>(),
        )
    };
    // 使用 assert! 确保字节切片的总大小等于 TaskInfo 的大小
    assert!(
        byte_slices.iter().map(|slice| slice.len()).sum::<usize>()
            == core::mem::size_of::<TaskInfo>(),
        "Byte slices do not match the size of TaskInfo"
    );
    // 把 task_info_bytes 拷贝到 byte_slices 中
    let mut offset = 0;
    for slice in byte_slices {
        let len = slice.len();
        slice.copy_from_slice(&task_info_bytes[offset..offset + len]);
        offset += len;
    }
    0 // 成功返回 0
}

/// YOUR JOB: Implement mmap.
pub fn sys_mmap(_start: usize, _len: usize, _port: usize) -> isize {
    trace!("kernel:pid[{}] sys_mmap", current_task().unwrap().pid.0);
    // 检查 start 是否未对齐
    if _start & 0x7 != 0 {
        println!("Start is not page-aligned. _start = {:x}", _start);
        return -1; // 或者根据需要处理错误
    }
    // len 如果为0就什么都不做
    if _len == 0 {
        return 0;
    }
    // port 其余位必须为 0
    if _port & !0x7 != 0 {
        println!("Port contains non-zero bits beyond the lowest three bits (it must be aligned to a multiple of 8).");
        return -1; // 或者根据需要处理错误
    }
    // 检查 port 是否有效
    if _port & 0x7 == 0 {
        println!("Port is invalid.");
        return -1; // 或者根据需要处理错误
    }
    if range_is_mapped(current_user_token(), _start.into(), (_start + _len).into()) {
        println!("Already mapped.");
        return -1; // 或者根据需要处理错误
    }
    insert_current_task_frame(_start, _len, _port);
    0
}

/// YOUR JOB: Implement munmap.
pub fn sys_munmap(_start: usize, _len: usize) -> isize {
    trace!("kernel:pid[{}] sys_munmap", current_task().unwrap().pid.0);
    // 检查 start 是否未对齐
    if _start & 0x7 != 0 {
        println!("Start is not page-aligned. _start = {:x}", _start);
        return -1; // 或者根据需要处理错误
    }
    // len 如果为0就什么都不做
    if _len == 0 {
        return 0;
    }
    if range_is_unmapped(current_user_token(), _start.into(), (_start + _len).into()) {
        println!("Already unmapped.");
        return -1; // 或者根据需要处理错误
    }
    free_current_task_frame(_start, _len);
    0
}

/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel:pid[{}] sys_sbrk", current_task().unwrap().pid.0);
    if let Some(old_brk) = current_task().unwrap().change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}

/// YOUR JOB: Implement spawn.
/// HINT: fork + exec =/= spawn
pub fn sys_spawn(_path: *const u8) -> isize {
    trace!("kernel:pid[{}] sys_spawn", current_task().unwrap().pid.0);
    let token = current_user_token();
    let path = translated_str(token, _path);
    if let Some(data) = get_app_data_by_name(path.as_str()) {
        let current_task = current_task().unwrap();
        let new_task = current_task.spawn(data);
        let new_pid = new_task.pid.0;
        // modify trap context of new_task, because it returns immediately after switching
        let trap_cx = new_task.inner_exclusive_access().get_trap_cx();
        // we do not have to move to next instruction since we have done it before
        // for child process, fork returns 0
        trap_cx.x[10] = 0;
        // add new task to scheduler
        add_task(new_task);
        new_pid as isize
    } else {
        println!("Invalid task name.");
        -1
    }
}

// YOUR JOB: Set task priority.
pub fn sys_set_priority(_prio: isize) -> isize {
    trace!(
        "kernel:pid[{}] sys_set_priority",
        current_task().unwrap().pid.0
    );
    if _prio < 2 {
        return -1;
    }
    let task = current_task().unwrap();
    task.inner_exclusive_access().task_priority = _prio;
    task.inner_exclusive_access().task_pass = BIG_STRIDE / _prio;
    _prio
}
