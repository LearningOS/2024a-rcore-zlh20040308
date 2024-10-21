//! Process management syscalls
use crate::mm::{range_is_mapped, range_is_unmapped, translated_byte_buffer};
use crate::{
    config::MAX_SYSCALL_NUM,
    task::{
        change_program_brk, current_user_token, exit_current_and_run_next, free_current_task_frame,
        get_current_task_status, get_current_task_syscall_times,
        get_current_task_total_running_time, insert_current_task_frame,
        suspend_current_and_run_next, TaskStatus,
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
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");

    // 获取当前进程的页表 token
    let token = current_user_token();

    // 将用户传入的指针 ts 转换为内核可以访问的字节缓冲区
    let byte_slices =
        translated_byte_buffer(token, ts as *const u8, core::mem::size_of::<TimeVal>());

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
    trace!("kernel: sys_task_info");

    // 获取当前进程的页表 token
    let token = current_user_token();

    // 将用户传入的指针 _ti 转换为内核可以访问的字节缓冲区
    let byte_slices =
        translated_byte_buffer(token, _ti as *const u8, core::mem::size_of::<TaskInfo>());

    // 创建一个 TaskInfo 实例，填充当前任务的信息
    let task_info = TaskInfo {
        status: get_current_task_status(),
        syscall_times: get_current_task_syscall_times(),
        time: get_current_task_total_running_time(),
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

// YOUR JOB: Implement mmap.
pub fn sys_mmap(_start: usize, _len: usize, _port: usize) -> isize {
    trace!("kernel: sys_mmap");
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

// YOUR JOB: Implement munmap.
pub fn sys_munmap(_start: usize, _len: usize) -> isize {
    trace!("kernel: sys_munmap");

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
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
