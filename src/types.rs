use bitflags::bitflags;
use perf_event_open_sys::bindings::*;

bitflags! {
    pub struct SampleFormat: u64 {
        const IP = PERF_SAMPLE_IP;
        const TID = PERF_SAMPLE_TID;
        const TIME = PERF_SAMPLE_TIME;
        const ADDR = PERF_SAMPLE_ADDR;
        const READ = PERF_SAMPLE_READ;
        const CALLCHAIN = PERF_SAMPLE_CALLCHAIN;
        const ID = PERF_SAMPLE_ID;
        const CPU = PERF_SAMPLE_CPU;
        const PERIOD = PERF_SAMPLE_PERIOD;
        const STREAM_ID = PERF_SAMPLE_STREAM_ID;
        const RAW = PERF_SAMPLE_RAW;
        const BRANCH_STACK = PERF_SAMPLE_BRANCH_STACK;
        const REGS_USER = PERF_SAMPLE_REGS_USER;
        const STACK_USER = PERF_SAMPLE_STACK_USER;
        const WEIGHT = PERF_SAMPLE_WEIGHT;
        const DATA_SRC = PERF_SAMPLE_DATA_SRC;
        const IDENTIFIER = PERF_SAMPLE_IDENTIFIER;
        const TRANSACTION = PERF_SAMPLE_TRANSACTION;
        const REGS_INTR = PERF_SAMPLE_REGS_INTR;
        const PHYS_ADDR = PERF_SAMPLE_PHYS_ADDR;
        const AUX = PERF_SAMPLE_AUX;
        const CGROUP = PERF_SAMPLE_CGROUP;
        const DATA_PAGE_SIZE = PERF_SAMPLE_DATA_PAGE_SIZE;
        const CODE_PAGE_SIZE = PERF_SAMPLE_CODE_PAGE_SIZE;
        const WEIGHT_STRUCT = PERF_SAMPLE_WEIGHT_STRUCT;
    }

    pub struct BranchSampleFormat: u64 {
        /// user branches
        const USER = PERF_SAMPLE_BRANCH_USER as u64;
        /// kernel branches
        const KERNEL = PERF_SAMPLE_BRANCH_KERNEL as u64;
        /// hypervisor branches
        const HV = PERF_SAMPLE_BRANCH_HV as u64;
        /// any branch types
        const ANY = PERF_SAMPLE_BRANCH_ANY as u64;
        /// any call branch
        const ANY_CALL = PERF_SAMPLE_BRANCH_ANY_CALL as u64;
        /// any return branch
        const ANY_RETURN = PERF_SAMPLE_BRANCH_ANY_RETURN as u64;
        /// indirect calls
        const IND_CALL = PERF_SAMPLE_BRANCH_IND_CALL as u64;
        /// transaction aborts
        const ABORT_TX = PERF_SAMPLE_BRANCH_ABORT_TX as u64;
        /// in transaction
        const IN_TX = PERF_SAMPLE_BRANCH_IN_TX as u64;
        /// not in transaction
        const NO_TX = PERF_SAMPLE_BRANCH_NO_TX as u64;
        /// conditional branches
        const COND = PERF_SAMPLE_BRANCH_COND as u64;
        /// call/ret stack
        const CALL_STACK = PERF_SAMPLE_BRANCH_CALL_STACK as u64;
        /// indirect jumps
        const IND_JUMP = PERF_SAMPLE_BRANCH_IND_JUMP as u64;
        /// direct call
        const CALL = PERF_SAMPLE_BRANCH_CALL as u64;
        /// no flags
        const NO_FLAGS = PERF_SAMPLE_BRANCH_NO_FLAGS as u64;
        /// no cycles
        const NO_CYCLES = PERF_SAMPLE_BRANCH_NO_CYCLES as u64;
        /// save branch type
        const TYPE_SAVE = PERF_SAMPLE_BRANCH_TYPE_SAVE as u64;
        /// save low level index of raw branch records
        const HW_INDEX = PERF_SAMPLE_BRANCH_HW_INDEX as u64;
    }

    pub struct AttrFlags: u64 {
        /// off by default
        const DISABLED = 0;
        /// children inherit it
        const INHERIT = 0;
        /// must always be on PMU
        const PINNED = 0;
        /// only group on PMU
        const EXCLUSIVE = 0;
        /// don't count user
        const EXCLUDE_USER = 0;
        /// don't count kernel
        const EXCLUDE_KERNEL = 0;
        /// don't count hypervisor
        const EXCLUDE_HV = 0;
        /// don't count when idle
        const EXCLUDE_IDLE = 0;
        /// include mmap data
        const MMAP = 0;
        /// include comm data
        const COMM = 0;
        /// use freq, not period
        const FREQ = 0;
        /// per task counts
        const INHERIT_STAT = 0;
        /// next exec enables
        const ENABLE_ON_EXEC = 0;
        /// trace fork/exit
        const TASK = 0;
        /// wakeup_watermark
        const WATERMARK = 0;
        /// one of the two PRECISE_IP bitmask bits
        const PRECISE_IP_BIT_15 = 1 << 15;
        /// one of the two PRECISE_IP bitmask bits
        const PRECISE_IP_BIT_16 = 1 << 16;
        /// the full PRECISE_IP bitmask
        const PRECISE_IP_BITMASK = 0;
        /// non-exec mmap data
        const MMAP_DATA = 0;
        /// sample_type all events
        const SAMPLE_ID_ALL = 0;
        /// don't count in host
        const EXCLUDE_HOST = 0;
        /// don't count in guest
        const EXCLUDE_GUEST = 0;
        /// exclude kernel callchains
        const EXCLUDE_CALLCHAIN_KERNEL = 0;
        /// exclude user callchains
        const EXCLUDE_CALLCHAIN_USER = 0;
        /// include mmap with inode data
        const MMAP2 = 0;
        /// flag comm events that are due to exec
        const COMM_EXEC = 0;
        /// use @clockid for time fields
        const USE_CLOCKID = 0;
        /// context switch data
        const CONTEXT_SWITCH = 0;
        /// Write ring buffer from end to beginning
        const WRITE_BACKWARD = 0;
        /// include namespaces data
        const NAMESPACES = 0;
        /// include ksymbol events
        const KSYMBOL = 0;
        /// include bpf events
        const BPF_EVENT = 0;
        /// generate AUX records instead of events
        const AUX_OUTPUT = 0;
        /// include cgroup events
        const CGROUP = 0;
        /// include text poke events
        const TEXT_POKE = 0;
        /// use build id in mmap2 events
        const BUILD_ID = 0;
        /// children only inherit if cloned with CLONE_THREAD
        const INHERIT_THREAD = 0;
        /// event is removed from task on exec
        const REMOVE_ON_EXEC = 0;
        /// send synchronous SIGTRAP on event
        const SIGTRAP = 0;
    }

    pub struct HwBreakpointType: u32 {
        /// No breakpoint. (`HW_BREAKPOINT_EMPTY`)
        const EMPTY = 0;
        /// Count when we read the memory location. (`HW_BREAKPOINT_R`)
        const R = 1;
        /// Count when we write the memory location. (`HW_BREAKPOINT_W`)
        const W = 2;
        /// Count when we read or write the memory location. (`HW_BREAKPOINT_RW`)
        const RW = Self::R.bits | Self::W.bits;
        /// Count when we execute code at the memory location. (`HW_BREAKPOINT_X`)
        const X = 4;
        /// The combination of `HW_BREAKPOINT_R` or `HW_BREAKPOINT_W` with
        //// `HW_BREAKPOINT_X` is not allowed. (`HW_BREAKPOINT_INVALID`)
        const INVALID = Self::RW.bits | Self::X.bits;
    }

    /// The format of the data returned by read() on a perf event fd,
    /// as specified by attr.read_format:
    ///
    /// ```pseudo-c
    /// struct read_format {
    /// 	{ u64 value;
    /// 	  { u64 time_enabled; } && PERF_FORMAT_TOTAL_TIME_ENABLED
    /// 	  { u64 time_running; } && PERF_FORMAT_TOTAL_TIME_RUNNING
    /// 	  { u64 id;           } && PERF_FORMAT_ID
    /// 	} && !PERF_FORMAT_GROUP
    ///
    /// 	{ u64 nr;
    /// 	  { u64 time_enabled; } && PERF_FORMAT_TOTAL_TIME_ENABLED
    /// 	  { u64 time_running; } && PERF_FORMAT_TOTAL_TIME_RUNNING
    /// 	  { u64 value;
    /// 	    { u64	id;           } && PERF_FORMAT_ID
    /// 	  } cntr[nr];
    /// 	} && PERF_FORMAT_GROUP
    /// };
    /// ```
    pub struct ReadFormat: u64 {
        const TOTAL_TIME_ENABLED = PERF_FORMAT_TOTAL_TIME_ENABLED as u64;
        const TOTAL_TIME_RUNNING = PERF_FORMAT_TOTAL_TIME_RUNNING as u64;
        const ID = PERF_FORMAT_ID as u64;
        const GROUP = PERF_FORMAT_GROUP as u64;
    }
}

/// Specifies how precise the instruction address should be.
/// With `perf record -e` you can set the precision by appending /p to the
/// event name, with varying numbers of `p`s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IpSkidConstraint {
    /// 0 - SAMPLE_IP can have arbitrary skid
    ArbitrarySkid,
    /// 1 - SAMPLE_IP must have constant skid
    ConstantSkid,
    /// 2 - SAMPLE_IP requested to have 0 skid
    ZeroSkid,
    /// 3 - SAMPLE_IP must have 0 skid, or uses randomization to avoid
    /// sample shadowing effects.
    ZeroSkidOrRandomization,
}

impl AttrFlags {
    /// Extract the IpSkidConstraint from the bits.
    pub fn ip_skid_constraint(&self) -> IpSkidConstraint {
        match (self.bits & Self::PRECISE_IP_BITMASK.bits) >> 15 {
            0 => IpSkidConstraint::ArbitrarySkid,
            1 => IpSkidConstraint::ConstantSkid,
            2 => IpSkidConstraint::ZeroSkid,
            3 => IpSkidConstraint::ZeroSkidOrRandomization,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ClockId {
    Realtime,
    Monotonic,
    ProcessCputimeId,
    ThreadCputimeId,
    MonotonicRaw,
    RealtimeCoarse,
    MonotonicCoarse,
    Boottime,
    RealtimeAlarm,
    BoottimeAlarm,
}

impl ClockId {
    pub fn from_u32(clockid: u32) -> Option<Self> {
        Some(match clockid {
            0 => Self::Realtime,
            1 => Self::Monotonic,
            2 => Self::ProcessCputimeId,
            3 => Self::ThreadCputimeId,
            4 => Self::MonotonicRaw,
            5 => Self::RealtimeCoarse,
            6 => Self::MonotonicCoarse,
            7 => Self::Boottime,
            8 => Self::RealtimeAlarm,
            9 => Self::BoottimeAlarm,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordType(pub u32);

impl RecordType {
    // Kernel-built-in record types
    pub const MMAP: Self = Self(PERF_RECORD_MMAP);
    pub const LOST: Self = Self(PERF_RECORD_LOST);
    pub const COMM: Self = Self(PERF_RECORD_COMM);
    pub const EXIT: Self = Self(PERF_RECORD_EXIT);
    pub const THROTTLE: Self = Self(PERF_RECORD_THROTTLE);
    pub const UNTHROTTLE: Self = Self(PERF_RECORD_UNTHROTTLE);
    pub const FORK: Self = Self(PERF_RECORD_FORK);
    pub const READ: Self = Self(PERF_RECORD_READ);
    pub const SAMPLE: Self = Self(PERF_RECORD_SAMPLE);
    pub const MMAP2: Self = Self(PERF_RECORD_MMAP2);
    pub const AUX: Self = Self(PERF_RECORD_AUX);
    pub const ITRACE_START: Self = Self(PERF_RECORD_ITRACE_START);
    pub const LOST_SAMPLES: Self = Self(PERF_RECORD_LOST_SAMPLES);
    pub const SWITCH: Self = Self(PERF_RECORD_SWITCH);
    pub const SWITCH_CPU_WIDE: Self = Self(PERF_RECORD_SWITCH_CPU_WIDE);
    pub const NAMESPACES: Self = Self(PERF_RECORD_NAMESPACES);
    pub const KSYMBOL: Self = Self(PERF_RECORD_KSYMBOL);
    pub const BPF_EVENT: Self = Self(PERF_RECORD_BPF_EVENT);
    pub const CGROUP: Self = Self(PERF_RECORD_CGROUP);
    pub const TEXT_POKE: Self = Self(PERF_RECORD_TEXT_POKE);
    pub const AUX_OUTPUT_HW_ID: Self = Self(PERF_RECORD_AUX_OUTPUT_HW_ID);

    pub const USER_TYPE_START: u32 = 64;

    pub fn is_builtin_type(&self) -> bool {
        self.0 < Self::USER_TYPE_START
    }

    pub fn is_user_type(&self) -> bool {
        self.0 >= Self::USER_TYPE_START
    }
}

impl std::fmt::Debug for RecordType {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        let s = match *self {
            Self::MMAP => "MMAP",
            Self::LOST => "LOST",
            Self::COMM => "COMM",
            Self::EXIT => "EXIT",
            Self::THROTTLE => "THROTTLE",
            Self::UNTHROTTLE => "UNTHROTTLE",
            Self::FORK => "FORK",
            Self::READ => "READ",
            Self::SAMPLE => "SAMPLE",
            Self::MMAP2 => "MMAP2",
            Self::AUX => "AUX",
            Self::ITRACE_START => "ITRACE_START",
            Self::LOST_SAMPLES => "LOST_SAMPLES",
            Self::SWITCH => "SWITCH",
            Self::SWITCH_CPU_WIDE => "SWITCH_CPU_WIDE",
            Self::NAMESPACES => "NAMESPACES",
            Self::KSYMBOL => "KSYMBOL",
            Self::BPF_EVENT => "BPF_EVENT",
            Self::CGROUP => "CGROUP",
            Self::TEXT_POKE => "TEXT_POKE",
            Self::AUX_OUTPUT_HW_ID => "AUX_OUTPUT_HW_ID",
            other if self.is_builtin_type() => {
                return fmt.write_fmt(format_args!("Unknown built-in: {}", other.0));
            }
            other => {
                return fmt.write_fmt(format_args!("User type: {}", other.0));
            }
        };
        fmt.write_str(s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CpuMode {
    Unknown,
    Kernel,
    User,
    Hypervisor,
    GuestKernel,
    GuestUser,
}

impl CpuMode {
    /// Initialize from the misc field of the perf event header.
    pub fn from_misc(misc: u16) -> Self {
        match misc as u32 & PERF_RECORD_MISC_CPUMODE_MASK {
            PERF_RECORD_MISC_CPUMODE_UNKNOWN => Self::Unknown,
            PERF_RECORD_MISC_KERNEL => Self::Kernel,
            PERF_RECORD_MISC_USER => Self::User,
            PERF_RECORD_MISC_HYPERVISOR => Self::Hypervisor,
            PERF_RECORD_MISC_GUEST_KERNEL => Self::GuestKernel,
            PERF_RECORD_MISC_GUEST_USER => Self::GuestUser,
            _ => Self::Unknown,
        }
    }
}
