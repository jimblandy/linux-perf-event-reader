use crate::types::*;
use byteorder::{ByteOrder, ReadBytesExt};
use perf_event_open_sys::bindings as sys;
use std::io::Read;
use std::num::NonZeroU64;
use std::{cmp, io, mem, slice};

/// `perf_event_header`
#[derive(Debug, Clone, Copy)]
pub struct PerfEventHeader {
    pub type_: u32,
    pub misc: u16,
    pub size: u16,
}

impl PerfEventHeader {
    pub const STRUCT_SIZE: usize = 4 + 2 + 2;

    pub fn parse<R: Read, T: ByteOrder>(mut reader: R) -> Result<Self, std::io::Error> {
        let type_ = reader.read_u32::<T>()?;
        let misc = reader.read_u16::<T>()?;
        let size = reader.read_u16::<T>()?;
        Ok(Self { type_, misc, size })
    }
}

/// `perf_event_attr`
#[derive(Debug, Clone, Copy)]
pub struct PerfEventAttr {
    r#type: PerfEventType,
    perf_clock: PerfClock,
    raw: sys::perf_event_attr,
}

impl PerfEventAttr {
    /// Read a `PerfEventAttr` struct from `reader`.
    ///
    /// If given, `size` is the actual byte length of the struct. This
    /// overrides whatever value is given in the `perf_event_attr`
    /// struct's `size` field.
    ///
    /// The Linux kernel establishes conventions for handling structs
    /// that need to be able to acquire new fields over time:
    ///
    /// - Each struct is accompanied by an indication of how large
    ///   userspace thinks it is. (This is either our `size` argument
    ///   or the struct's own `size` field.)
    ///
    /// - Once placed, fields are never moved. New fields are only added at the end.
    ///   Deleted fields become placeholders.
    ///
    /// - Filling a field with zero bits always requests the same
    ///   behavior as before the field was defined.
    ///
    /// Following these rules, it is always meaning-preserving to pad
    /// short data at the end with zeros, or to skip long data as long
    /// as it only contains zeros. If the excess bytes contain any
    /// non-zero bytes, we report an error.
    pub fn parse<R: Read>(mut reader: R, size: Option<u32>) -> Result<Self, std::io::Error> {
        // This is a little awkward, as there are four lengths in play here:
        //
        // - The length of our `sys::perf_event_attr` type.
        //
        // - The length stored in the `perf_event_attr` struct's `size` field.
        //
        // - The length passed as the `size` argument.
        //
        // - The length of the data available in `reader`.

        // Start with a `perf_event_attr` filled with zeros. As described above,
        // if there is not enough data to initialize this fully, the remaining
        // zeroed tail of the struct will not affect the meaning.
        //
        // Safety: all bit patterns are valid representations of
        // `perf_event_attr` values.
        let mut raw: sys::perf_event_attr = unsafe { mem::zeroed() };
        const ATTR_SIZE: usize = mem::size_of::<sys::perf_event_attr>();

        // Read only enough to initialize `raw.size`.
        reader
            .read_exact(unsafe { slice::from_raw_parts_mut(&mut raw as *mut _ as *mut u8, 8) })?;

        // Decide how many bytes we will read, and how many bytes we will use.
        //
        // If `size` is `Some(n)`, read `n` bytes. If it's `None`, then read
        // `raw.size` bytes.
        //
        // Use the lesser of `size` (if given), `raw.size` and the size of our
        // `perf_event_attr` struct.
        //
        // Special case: if `raw.size` is zero, then we should assume
        // `PERF_ATTR_SIZE_VER0`a per Linux `kernel/events/core.c`, which says:
        //
        //     /* ABI compatibility quirk: */
        //     if (!size)
        //         size = PERF_ATTR_SIZE_VER0;
        //
        // We're unlikely to encounter this, but it's easy enough to handle.
        if raw.size == 0 {
            raw.size = sys::PERF_ATTR_SIZE_VER0;
        }
        let to_read = size.unwrap_or(raw.size) as usize;
        let to_use = cmp::min(to_read, cmp::min(raw.size as usize, ATTR_SIZE));

        let mut rest = unsafe {
            let whole = slice::from_raw_parts_mut(&mut raw as *mut _ as *mut u8, ATTR_SIZE);
            &mut whole[8..to_use]
        };
        // Unfortunately, we can't use read_exact here, because we want to
        // handle short reads, so just write it out. Short reads may occur when
        // reading data generated using an older version of the kernel headers
        // than we were compiled against ourselves.
        while !rest.is_empty() {
            let read = match reader.read(rest) {
                Ok(0) => break,                                        // end of input
                Ok(bytes) => bytes,                                    // progress
                Err(e) if e.kind() == io::ErrorKind::Interrupted => 0, // just retry
                Err(other) => return Err(other),                       // actual error
            };
            rest = &mut rest[read..];
        }

        // If there is additional data beyond the end of our `perf_event_attr`
        // struct, check that it is all zeros. This may occur when reading data
        // generated using a newer version of the kernel headers than we were
        // compiled against ourselves.
        let read_thus_far = to_use - rest.len();
        if to_read > read_thus_far {
            let mut excess = vec![];
            reader
                .by_ref()
                .take((to_read - read_thus_far) as u64)
                .read_to_end(&mut excess)?;
            if !excess.iter().all(|&b| b == 0) {
                let msg = "perf data uses features too new for this program to handle";
                return Err(io::Error::new(io::ErrorKind::Other, msg));
            }
        }

        let r#type = PerfEventType::parse(
            raw.type_,
            raw.bp_type,
            raw.config,
            // Safety: all bit patterns are valid u64 values.
            unsafe { raw.__bindgen_anon_3.config1 },
            unsafe { raw.__bindgen_anon_4.config2 },
        )
            .ok_or(io::ErrorKind::InvalidInput)?;

        let perf_clock = if raw.use_clockid() != 0 {
            let clockid = ClockId::from_i32(raw.clockid).ok_or(io::ErrorKind::InvalidInput)?;
            PerfClock::ClockId(clockid)
        } else {
            PerfClock::Default
        };

        Ok(Self { r#type, perf_clock, raw })
    }
}

impl PerfEventAttr {
    pub fn r#type(&self) -> PerfEventType {
        self.r#type
    }

    pub fn sample_format(&self) -> SampleFormat {
        SampleFormat::from_bits_truncate(self.raw.sample_type)
    }

    pub fn sampling_policy(&self) -> SamplingPolicy {
        if self.freq() {
            SamplingPolicy::Frequency(unsafe { self.raw.__bindgen_anon_1.sample_freq })
        } else if let Some(period) =
            NonZeroU64::new(unsafe { self.raw.__bindgen_anon_1.sample_period })
        {
            SamplingPolicy::Period(period)
        } else {
            SamplingPolicy::NoSampling
        }
    }

    pub fn wakeup_policy(&self) -> WakeupPolicy {
        if self.watermark() {
            WakeupPolicy::Watermark(unsafe { self.raw.__bindgen_anon_2.wakeup_watermark })
        } else {
            WakeupPolicy::EventCount(unsafe { self.raw.__bindgen_anon_2.wakeup_events })
        }
    }

    pub fn branch_sample_format(&self) -> BranchSampleFormat {
        BranchSampleFormat::from_bits_truncate(self.raw.branch_sample_type)
    }

    /// Specifies the structure values returned by read() on a perf event fd,
    /// see [`ReadFormat`].
    pub fn read_format(&self) -> ReadFormat {
        ReadFormat::from_bits_truncate(self.raw.read_format)
    }

    pub fn perf_clock(&self) -> PerfClock {
        self.perf_clock
    }

    pub fn disabled(&self) -> bool {
        self.raw.disabled() != 0
    }

    pub fn inherit(&self) -> bool {
        self.raw.inherit() != 0
    }

    pub fn pinned(&self) -> bool {
        self.raw.pinned() != 0
    }

    pub fn exclusive(&self) -> bool {
        self.raw.exclusive() != 0
    }

    pub fn exclude_user(&self) -> bool {
        self.raw.exclude_user() != 0
    }

    pub fn exclude_kernel(&self) -> bool {
        self.raw.exclude_kernel() != 0
    }

    pub fn exclude_hv(&self) -> bool {
        self.raw.exclude_hv() != 0
    }

    pub fn exclude_idle(&self) -> bool {
        self.raw.exclude_idle() != 0
    }

    pub fn mmap(&self) -> bool {
        self.raw.mmap() != 0
    }

    pub fn comm(&self) -> bool {
        self.raw.comm() != 0
    }

    pub fn freq(&self) -> bool {
        self.raw.freq() != 0
    }

    pub fn inherit_stat(&self) -> bool {
        self.raw.inherit_stat() != 0
    }

    pub fn enable_on_exec(&self) -> bool {
        self.raw.enable_on_exec() != 0
    }

    pub fn task(&self) -> bool {
        self.raw.task() != 0
    }

    pub fn watermark(&self) -> bool {
        self.raw.watermark() != 0
    }

    pub fn precise_ip(&self) -> IpSkidConstraint {
        IpSkidConstraint::from_bits(self.raw.precise_ip())
    }

    pub fn mmap_data(&self) -> bool {
        self.raw.mmap_data() != 0
    }

    pub fn sample_id_all(&self) -> bool {
        self.raw.sample_id_all() != 0
    }

    pub fn exclude_host(&self) -> bool {
        self.raw.exclude_host() != 0
    }

    pub fn exclude_guest(&self) -> bool {
        self.raw.exclude_guest() != 0
    }

    pub fn exclude_callchain_kernel(&self) -> bool {
        self.raw.exclude_callchain_kernel() != 0
    }

    pub fn exclude_callchain_user(&self) -> bool {
        self.raw.exclude_callchain_user() != 0
    }

    pub fn mmap2(&self) -> bool {
        self.raw.mmap2() != 0
    }

    pub fn comm_exec(&self) -> bool {
        self.raw.comm_exec() != 0
    }

    pub fn use_clockid(&self) -> bool {
        self.raw.use_clockid() != 0
    }

    pub fn context_switch(&self) -> bool {
        self.raw.context_switch() != 0
    }

    pub fn write_backward(&self) -> bool {
        self.raw.write_backward() != 0
    }

    pub fn namespaces(&self) -> bool {
        self.raw.namespaces() != 0
    }

    pub fn ksymbol(&self) -> bool {
        self.raw.ksymbol() != 0
    }

    pub fn bpf_event(&self) -> bool {
        self.raw.bpf_event() != 0
    }

    pub fn aux_output(&self) -> bool {
        self.raw.aux_output() != 0
    }

    pub fn cgroup(&self) -> bool {
        self.raw.cgroup() != 0
    }

    pub fn text_poke(&self) -> bool {
        self.raw.text_poke() != 0
    }

    pub fn sample_regs_user(&self) -> u64 {
        self.raw.sample_regs_user
    }
}

/// The type of perf event
#[derive(Debug, Clone, Copy)]
pub enum PerfEventType {
    /// A hardware perf event. (`PERF_TYPE_HARDWARE`)
    Hardware(HardwareEventId, PmuTypeId),
    /// A software perf event. (`PERF_TYPE_SOFTWARE`)
    ///
    /// Special "software" events provided by the kernel, even if the hardware
    /// does not support performance events. These events measure various
    /// physical and sw events of the kernel (and allow the profiling of them as
    /// well).
    Software(SoftwareCounterType),
    /// A tracepoint perf event. (`PERF_TYPE_TRACEPOINT`)
    Tracepoint(u64),
    /// A hardware cache perf event. (`PERF_TYPE_HW_CACHE`)
    ///
    /// Selects a certain combination of CacheId, CacheOp, CacheOpResult, PMU type ID.
    ///
    /// ```plain
    /// { L1-D, L1-I, LLC, ITLB, DTLB, BPU, NODE } x
    /// { read, write, prefetch } x
    /// { accesses, misses }
    /// ```
    HwCache(
        HardwareCacheId,
        HardwareCacheOp,
        HardwareCacheOpResult,
        PmuTypeId,
    ),
    /// A hardware breakpoint perf event. (`PERF_TYPE_BREAKPOINT`)
    ///
    /// Breakpoints can be read/write accesses to an address as well as
    /// execution of an instruction address.
    Breakpoint(HwBreakpointType, HwBreakpointAddr, HwBreakpointLen),
    /// Dynamic PMU
    ///
    /// `(pmu, config, config1, config2)`
    ///
    /// Acceptable values for each of `config`, `config1` and `config2`
    /// parameters are defined by corresponding entries in
    /// `/sys/bus/event_source/devices/<pmu>/format/*`.
    ///
    /// From the `perf_event_open` man page:
    /// > Since Linux 2.6.38, perf_event_open() can support multiple PMUs.  To
    /// > enable this, a value exported by the kernel can be used in the type
    /// > field to indicate which PMU to use.  The value to use can be found in
    /// > the sysfs filesystem: there is a subdirectory per PMU instance under
    /// > /sys/bus/event_source/devices.  In each subdirectory there is a type
    /// > file whose content is an integer that can be used in the type field.
    /// > For instance, /sys/bus/event_source/devices/cpu/type contains the
    /// > value for the core CPU PMU, which is usually 4.
    ///
    /// (I don't fully understand this - the value 4 also means `PERF_TYPE_RAW`.
    /// Maybe the type `Raw` is just one of those dynamic PMUs, usually "core"?)
    ///
    /// Among the "dynamic PMU" values, there are two special values for
    /// kprobes and uprobes:
    ///
    /// > kprobe and uprobe (since Linux 4.17)
    /// > These two dynamic PMUs create a kprobe/uprobe and attach it to the
    /// > file descriptor generated by perf_event_open.  The kprobe/uprobe will
    /// > be destroyed on the destruction of the file descriptor.  See fields
    /// > kprobe_func, uprobe_path, kprobe_addr, and probe_offset for more details.
    ///
    /// ```c
    /// union {
    ///     __u64 kprobe_func; /* for perf_kprobe */
    ///     __u64 uprobe_path; /* for perf_uprobe */
    ///     __u64 config1; /* extension of config */
    /// };
    ///
    /// union {
    ///     __u64 kprobe_addr; /* when kprobe_func == NULL */
    ///     __u64 probe_offset; /* for perf_[k,u]probe */
    ///     __u64 config2; /* extension of config1 */
    /// };
    /// ```
    DynamicPmu(u32, u64, u64, u64),
}

/// PMU type ID
///
/// The PMU type ID allows selecting whether to observe only "atom", only "core",
/// or both. If the PMU type ID is zero, both "atom" and "core" are observed.
/// To observe just one of them, the PMU type ID needs to be set to the value of
/// `/sys/devices/cpu_atom/type` or of `/sys/devices/cpu_core/type`.
#[derive(Debug, Clone, Copy)]
pub struct PmuTypeId(pub u32);

/// The address of the breakpoint.
///
/// For execution breakpoints, this is the memory address of the instruction
/// of interest; for read and write breakpoints, it is the memory address of
/// the memory location of interest.
#[derive(Debug, Clone, Copy)]
pub struct HwBreakpointAddr(pub u64);

/// The length of the breakpoint being measured.
///
/// Options are `HW_BREAKPOINT_LEN_1`, `HW_BREAKPOINT_LEN_2`,
/// `HW_BREAKPOINT_LEN_4`, and `HW_BREAKPOINT_LEN_8`.  For an
/// execution breakpoint, set this to sizeof(long).
#[derive(Debug, Clone, Copy)]
pub struct HwBreakpointLen(pub u64);

impl PerfEventType {
    pub fn parse(
        type_: u32,
        bp_type: u32,
        config: u64,
        config1: u64,
        config2: u64,
    ) -> Option<Self> {
        let t = match type_ {
            sys::PERF_TYPE_HARDWARE => {
                // Config format: 0xEEEEEEEE000000AA
                //
                //  - AA: hardware event ID
                //  - EEEEEEEE: PMU type ID
                let hardware_event_id = (config & 0xff) as u8;
                let pmu_type = PmuTypeId((config >> 32) as u32);
                Self::Hardware(HardwareEventId::parse(hardware_event_id)?, pmu_type)
            }
            sys::PERF_TYPE_SOFTWARE => Self::Software(SoftwareCounterType::parse(config)?),
            sys::PERF_TYPE_TRACEPOINT => Self::Tracepoint(config),
            sys::PERF_TYPE_HW_CACHE => {
                // Config format: 0xEEEEEEEE00DDCCBB
                //
                //  - BB: hardware cache ID
                //  - CC: hardware cache op ID
                //  - DD: hardware cache op result ID
                //  - EEEEEEEE: PMU type ID
                let cache_id = config as u8;
                let cache_op_id = (config >> 8) as u8;
                let cache_op_result = (config >> 16) as u8;
                let pmu_type = PmuTypeId((config >> 32) as u32);
                Self::HwCache(
                    HardwareCacheId::parse(cache_id)?,
                    HardwareCacheOp::parse(cache_op_id)?,
                    HardwareCacheOpResult::parse(cache_op_result)?,
                    pmu_type,
                )
            }
            sys::PERF_TYPE_BREAKPOINT => {
                let bp_type = HwBreakpointType::from_bits_truncate(bp_type);
                Self::Breakpoint(bp_type, HwBreakpointAddr(config1), HwBreakpointLen(config2))
            }
            _ => Self::DynamicPmu(type_, config, config1, config2),
            // PERF_TYPE_RAW is handled as part of DynamicPmu.
        };
        Some(t)
    }
}

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum HardwareEventId {
    /// `PERF_COUNT_HW_CPU_CYCLES`
    CpuCycles,
    /// `PERF_COUNT_HW_INSTRUCTIONS`
    Instructions,
    /// `PERF_COUNT_HW_CACHE_REFERENCES`
    CacheReferences,
    /// `PERF_COUNT_HW_CACHE_MISSES`
    CacheMisses,
    /// `PERF_COUNT_HW_BRANCH_INSTRUCTIONS`
    BranchInstructions,
    /// `PERF_COUNT_HW_BRANCH_MISSES`
    BranchMisses,
    /// `PERF_COUNT_HW_BUS_CYCLES`
    BusCycles,
    /// `PERF_COUNT_HW_STALLED_CYCLES_FRONTEND`
    StalledCyclesFrontend,
    /// `PERF_COUNT_HW_STALLED_CYCLES_BACKEND`
    StalledCyclesBackend,
    /// `PERF_COUNT_HW_REF_CPU_CYCLES`
    RefCpuCycles,
}

impl HardwareEventId {
    pub fn parse(hardware_event_id: u8) -> Option<Self> {
        let t = match hardware_event_id as sys::perf_hw_id {
            sys::PERF_COUNT_HW_CPU_CYCLES => Self::CpuCycles,
            sys::PERF_COUNT_HW_INSTRUCTIONS => Self::Instructions,
            sys::PERF_COUNT_HW_CACHE_REFERENCES => Self::CacheReferences,
            sys::PERF_COUNT_HW_CACHE_MISSES => Self::CacheMisses,
            sys::PERF_COUNT_HW_BRANCH_INSTRUCTIONS => Self::BranchInstructions,
            sys::PERF_COUNT_HW_BRANCH_MISSES => Self::BranchMisses,
            sys::PERF_COUNT_HW_BUS_CYCLES => Self::BusCycles,
            sys::PERF_COUNT_HW_STALLED_CYCLES_FRONTEND => Self::StalledCyclesFrontend,
            sys::PERF_COUNT_HW_STALLED_CYCLES_BACKEND => Self::StalledCyclesBackend,
            sys::PERF_COUNT_HW_REF_CPU_CYCLES => Self::RefCpuCycles,
            _ => return None,
        };
        Some(t)
    }
}

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum SoftwareCounterType {
    /// `PERF_COUNT_SW_CPU_CLOCK`
    CpuClock,
    /// `PERF_COUNT_SW_TASK_CLOCK`
    TaskClock,
    /// `PERF_COUNT_SW_PAGE_FAULTS`
    PageFaults,
    /// `PERF_COUNT_SW_CONTEXT_SWITCHES`
    ContextSwitches,
    /// `PERF_COUNT_SW_CPU_MIGRATIONS`
    CpuMigrations,
    /// `PERF_COUNT_SW_PAGE_FAULTS_MIN`
    PageFaultsMin,
    /// `PERF_COUNT_SW_PAGE_FAULTS_MAJ`
    PageFaultsMaj,
    /// `PERF_COUNT_SW_ALIGNMENT_FAULTS`
    AlignmentFaults,
    /// `PERF_COUNT_SW_EMULATION_FAULTS`
    EmulationFaults,
    /// `PERF_COUNT_SW_DUMMY`
    Dummy,
    /// `PERF_COUNT_SW_BPF_OUTPUT`
    BpfOutput,
    /// `PERF_COUNT_SW_CGROUP_SWITCHES`
    CgroupSwitches,
}

impl SoftwareCounterType {
    pub fn parse(config: u64) -> Option<Self> {
        let t = match config as sys::perf_sw_ids {
            sys::PERF_COUNT_SW_CPU_CLOCK => Self::CpuClock,
            sys::PERF_COUNT_SW_TASK_CLOCK => Self::TaskClock,
            sys::PERF_COUNT_SW_PAGE_FAULTS => Self::PageFaults,
            sys::PERF_COUNT_SW_CONTEXT_SWITCHES => Self::ContextSwitches,
            sys::PERF_COUNT_SW_CPU_MIGRATIONS => Self::CpuMigrations,
            sys::PERF_COUNT_SW_PAGE_FAULTS_MIN => Self::PageFaultsMin,
            sys::PERF_COUNT_SW_PAGE_FAULTS_MAJ => Self::PageFaultsMaj,
            sys::PERF_COUNT_SW_ALIGNMENT_FAULTS => Self::AlignmentFaults,
            sys::PERF_COUNT_SW_EMULATION_FAULTS => Self::EmulationFaults,
            sys::PERF_COUNT_SW_DUMMY => Self::Dummy,
            sys::PERF_COUNT_SW_BPF_OUTPUT => Self::BpfOutput,
            sys::PERF_COUNT_SW_CGROUP_SWITCHES => Self::CgroupSwitches,
            _ => return None,
        };
        Some(t)
    }
}

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum HardwareCacheId {
    /// `PERF_COUNT_HW_CACHE_L1D`
    L1d,
    /// `PERF_COUNT_HW_CACHE_L1I`
    L1i,
    /// `PERF_COUNT_HW_CACHE_LL`
    Ll,
    /// `PERF_COUNT_HW_CACHE_DTLB`
    Dtlb,
    /// `PERF_COUNT_HW_CACHE_ITLB`
    Itlb,
    /// `PERF_COUNT_HW_CACHE_BPU`
    Bpu,
    /// `PERF_COUNT_HW_CACHE_NODE`
    Node,
}

impl HardwareCacheId {
    pub fn parse(cache_id: u8) -> Option<Self> {
        let rv = match cache_id as sys::perf_hw_cache_id {
            sys::PERF_COUNT_HW_CACHE_L1D => Self::L1d,
            sys::PERF_COUNT_HW_CACHE_L1I => Self::L1i,
            sys::PERF_COUNT_HW_CACHE_LL => Self::Ll,
            sys::PERF_COUNT_HW_CACHE_DTLB => Self::Dtlb,
            sys::PERF_COUNT_HW_CACHE_ITLB => Self::Itlb,
            sys::PERF_COUNT_HW_CACHE_BPU => Self::Bpu,
            sys::PERF_COUNT_HW_CACHE_NODE => Self::Node,
            _ => return None,
        };
        Some(rv)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum HardwareCacheOp {
    /// `PERF_COUNT_HW_CACHE_OP_READ`
    Read,
    /// `PERF_COUNT_HW_CACHE_OP_WRITE`
    Write,
    /// `PERF_COUNT_HW_CACHE_OP_PREFETCH`
    Prefetch,
}

impl HardwareCacheOp {
    pub fn parse(cache_op: u8) -> Option<Self> {
        match cache_op as sys::perf_hw_cache_op_id {
            sys::PERF_COUNT_HW_CACHE_OP_READ => Some(Self::Read),
            sys::PERF_COUNT_HW_CACHE_OP_WRITE => Some(Self::Write),
            sys::PERF_COUNT_HW_CACHE_OP_PREFETCH => Some(Self::Prefetch),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum HardwareCacheOpResult {
    /// `PERF_COUNT_HW_CACHE_RESULT_ACCESS`
    Access,
    /// `PERF_COUNT_HW_CACHE_RESULT_MISS`
    Miss,
}

impl HardwareCacheOpResult {
    pub fn parse(cache_op_result: u8) -> Option<Self> {
        match cache_op_result as sys::perf_hw_cache_op_result_id {
            sys::PERF_COUNT_HW_CACHE_RESULT_ACCESS => Some(Self::Access),
            sys::PERF_COUNT_HW_CACHE_RESULT_MISS => Some(Self::Miss),
            _ => None,
        }
    }
}

/// Sampling Policy
///
/// > Events can be set to notify when a threshold is crossed,
/// > indicating an overflow. [...]
/// >
/// > Overflows are generated only by sampling events (sample_period
/// > must have a nonzero value).
#[derive(Debug, Clone, Copy)]
pub enum SamplingPolicy {
    /// `NoSampling` means that the event is a count and not a sampling event.
    NoSampling,
    /// Sets a fixed sampling period for a sampling event, in the unit of the
    /// observed count / event.
    ///
    /// A "sampling" event is one that generates an overflow notification every
    /// N events, where N is given by the sampling period. A sampling event has
    /// a sampling period greater than zero.
    ///
    /// When an overflow occurs, requested data is recorded in the mmap buffer.
    /// The `SampleFormat` bitfield controls what data is recorded on each overflow.
    Period(NonZeroU64),
    /// Sets a frequency for a sampling event, in "samples per (wall-clock) second".
    ///
    /// This uses a dynamic period which is adjusted by the kernel to hit the
    /// desired frequency. The rate of adjustment is a timer tick.
    ///
    /// If `SampleFormat::PERIOD` is requested, the current period at the time of
    /// the sample is stored in the sample.
    Frequency(u64),
}

/// Wakeup policy for "overflow notifications". This controls the point at
/// which the `read` call completes. (TODO: double check this)
///
/// > There are two ways to generate overflow notifications.
/// >
/// > The first is to set a `WakeupPolicy`
/// > that will trigger if a certain number of samples or bytes have
/// > been written to the mmap ring buffer.
/// >
/// > The other way is by use of the PERF_EVENT_IOC_REFRESH ioctl.
/// > This ioctl adds to a counter that decrements each time the event
/// > overflows.  When nonzero, POLLIN is indicated, but once the
/// > counter reaches 0 POLLHUP is indicated and the underlying event
/// > is disabled.
#[derive(Debug, Clone, Copy)]
pub enum WakeupPolicy {
    /// Wake up every time N records of type `RecordType::SAMPLE` have been
    /// written to the mmap ring buffer.
    EventCount(u32),
    /// Wake up after N bytes of any record type have been written to the mmap
    /// ring buffer.
    ///
    /// To receive a wakeup after every single record, choose `Watermark(1)`.
    /// `Watermark(0)` is treated the same as `Watermark(1)`.
    Watermark(u32),
}

/// This allows selecting which internal Linux clock to use when generating
/// timestamps.
///
/// Setting a specific ClockId can make it easier to correlate perf sample
/// times with timestamps generated by other tools. For example, when sampling
/// applications which emit JITDUMP information, you'll usually select the
/// moonotonic clock. This makes it possible to correctly order perf event
/// records and JITDUMP records - those also usually use the monotonic clock.
#[derive(Debug, Clone, Copy)]
pub enum PerfClock {
    /// The default clock. If this is used, the timestamps in event records
    /// are obtained with `local_clock()` which is a hardware timestamp if
    /// available and the jiffies value if not.
    ///
    /// In practice, on x86_64 this seems to use ktime_get_ns() which is the
    /// number of nanoseconds since boot.
    Default,

    /// A specific clock.
    ClockId(ClockId),
}
