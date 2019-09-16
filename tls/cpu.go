package tls

const CacheLinePadSize = 64

// CacheLinePad is used to pad structs to avoid false sharing.
type CacheLinePad struct{ _ [CacheLinePadSize]byte }

// CacheLineSize is the CPU's assumed cache line size.
// There is currently no runtime detection of the real cache line size
// so we use the constant per GOARCH CacheLinePadSize as an approximation.
var CacheLineSize uintptr = CacheLinePadSize

var X86 x86

// The booleans in x86 contain the correspondingly named cpuid feature bit.
// HasAVX and HasAVX2 are only set if the OS does support XMM and YMM registers
// in addition to the cpuid feature bit being set.
// The struct is padded to avoid false sharing.
type x86 struct {
	_            CacheLinePad
	HasAES       bool
	HasADX       bool
	HasAVX       bool
	HasAVX2      bool
	HasBMI1      bool
	HasBMI2      bool
	HasERMS      bool
	HasFMA       bool
	HasOSXSAVE   bool
	HasPCLMULQDQ bool
	HasPOPCNT    bool
	HasSSE2      bool
	HasSSE3      bool
	HasSSSE3     bool
	HasSSE41     bool
	HasSSE42     bool
	_            CacheLinePad
}

var PPC64 ppc64

// For ppc64(le), it is safe to check only for ISA level starting on ISA v3.00,
// since there are no optional categories. There are some exceptions that also
// require kernel support to work (darn, scv), so there are feature bits for
// those as well. The minimum processor requirement is POWER8 (ISA 2.07).
// The struct is padded to avoid false sharing.
type ppc64 struct {
	_        CacheLinePad
	HasDARN  bool // Hardware random number generator (requires kernel enablement)
	HasSCV   bool // Syscall vectored (requires kernel enablement)
	IsPOWER8 bool // ISA v2.07 (POWER8)
	IsPOWER9 bool // ISA v3.00 (POWER9)
	_        CacheLinePad
}

var ARM arm

// The booleans in arm contain the correspondingly named cpu feature bit.
// The struct is padded to avoid false sharing.
type arm struct {
	_        CacheLinePad
	HasVFPv4 bool
	HasIDIVA bool
	_        CacheLinePad
}

var ARM64 arm64

// The booleans in arm64 contain the correspondingly named cpu feature bit.
// The struct is padded to avoid false sharing.
type arm64 struct {
	_           CacheLinePad
	HasFP       bool
	HasASIMD    bool
	HasEVTSTRM  bool
	HasAES      bool
	HasPMULL    bool
	HasSHA1     bool
	HasSHA2     bool
	HasCRC32    bool
	HasATOMICS  bool
	HasFPHP     bool
	HasASIMDHP  bool
	HasCPUID    bool
	HasASIMDRDM bool
	HasJSCVT    bool
	HasFCMA     bool
	HasLRCPC    bool
	HasDCPOP    bool
	HasSHA3     bool
	HasSM3      bool
	HasSM4      bool
	HasASIMDDP  bool
	HasSHA512   bool
	HasSVE      bool
	HasASIMDFHM bool
	_           CacheLinePad
}

var S390X s390x

type s390x struct {
	_               CacheLinePad
	HasZArch        bool // z architecture mode is active [mandatory]
	HasSTFLE        bool // store facility list extended [mandatory]
	HasLDisp        bool // long (20-bit) displacements [mandatory]
	HasEImm         bool // 32-bit immediates [mandatory]
	HasDFP          bool // decimal floating point
	HasETF3Enhanced bool // ETF-3 enhanced
	HasMSA          bool // message security assist (CPACF)
	HasAES          bool // KM-AES{128,192,256} functions
	HasAESCBC       bool // KMC-AES{128,192,256} functions
	HasAESCTR       bool // KMCTR-AES{128,192,256} functions
	HasAESGCM       bool // KMA-GCM-AES{128,192,256} functions
	HasGHASH        bool // KIMD-GHASH function
	HasSHA1         bool // K{I,L}MD-SHA-1 functions
	HasSHA256       bool // K{I,L}MD-SHA-256 functions
	HasSHA512       bool // K{I,L}MD-SHA-512 functions
	HasVX           bool // vector facility. Note: the runtime sets this when it processes auxv records.
	HasVE1          bool // vector-enhancement 1
	_               CacheLinePad
}
