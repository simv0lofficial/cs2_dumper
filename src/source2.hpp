#pragma once

// Source2 engine data structures for CS2 memory reading.
// All structs use #pragma pack(push, 1) with explicit padding
// to guarantee exact field offsets matching the game binary.

#include <cstdint>
#include <cstddef>

#pragma pack(push, 1)

// ============================================================
// client/input — KeyButton
// ============================================================

struct KeyButton {
    uint8_t  pad_0[0x8];    // 0x0000
    uint64_t name;          // 0x0008 — ptr to null-terminated string
    uint8_t  pad_1[0x20];   // 0x0010
    uint32_t state;         // 0x0030
    uint8_t  pad_2[0x54];   // 0x0034
    uint64_t next;          // 0x0088 — ptr to next KeyButton
};

static_assert(offsetof(KeyButton, name)  == 0x0008);
static_assert(offsetof(KeyButton, state) == 0x0030);
static_assert(offsetof(KeyButton, next)  == 0x0088);
static_assert(sizeof(KeyButton) == 0x0090);

// ============================================================
// tier1/interface — InterfaceReg
// ============================================================

struct InterfaceReg {
    uint64_t create_fn;     // 0x0000
    uint64_t name;          // 0x0008 — ptr to string
    uint64_t next;          // 0x0010 — ptr to next InterfaceReg
};

static_assert(sizeof(InterfaceReg) == 0x0018);

// ============================================================
// tier0 — TsList
// ============================================================

struct TsListHead {
    uint64_t next;          // 0x0000 — Pointer to TsListNode
};

struct TsListBase {
    TsListHead head;        // 0x0000
};

// ============================================================
// tier1 — UtlMemoryPool
// ============================================================

struct UtlMemoryPool {
    int32_t  block_size;        // 0x0000
    int32_t  blocks_per_blob;   // 0x0004
    uint32_t grow_mode;         // 0x0008
    int32_t  blocks_allocated;  // 0x000C
    int32_t  peak_allocated;    // 0x0010
    uint16_t alignment_val;     // 0x0014
    uint16_t blob_count;        // 0x0016
    uint8_t  pad_0[0x8];       // 0x0018  (2 explicit + 6 alignment = 8)
    uint64_t free_list_head;    // 0x0020  (TsListBase.head.next)
    uint8_t  pad_1[0x20];      // 0x0028
    uint64_t blob_head;         // 0x0048
    int32_t  total_size;        // 0x0050
    uint8_t  pad_2[0xC];       // 0x0054
};

static_assert(offsetof(UtlMemoryPool, free_list_head) == 0x0020);
static_assert(offsetof(UtlMemoryPool, blob_head) == 0x0048);
static_assert(sizeof(UtlMemoryPool) == 0x0060);

// ============================================================
// tier1 — UtlTsHash helpers
// ============================================================

struct UtlTsHashBucket {
    uint64_t add_lock;            // 0x0000 (usize on x64)
    uint64_t first;               // 0x0008
    uint64_t first_uncommitted;   // 0x0010
};

static_assert(sizeof(UtlTsHashBucket) == 24);

struct UtlTsHashFixedData {
    uint64_t ui_key;    // 0x0000
    uint64_t next;      // 0x0008 — ptr to next UtlTsHashFixedData
    uint64_t data;      // 0x0010 — ptr to data (e.g. SchemaClassBinding)
};

static_assert(sizeof(UtlTsHashFixedData) == 24);

struct UtlTsHashAllocatedBlob {
    uint64_t next;          // 0x0000 — ptr to next blob
    uint8_t  pad_0[0x8];   // 0x0008
    uint64_t data;          // 0x0010 — ptr to data
    uint8_t  pad_1[0x18];  // 0x0018
};

static_assert(sizeof(UtlTsHashAllocatedBlob) == 0x0030);

// ============================================================
// tier1 — UtlTsHash (256 buckets, default)
// ============================================================

constexpr int UTL_TS_HASH_BUCKET_COUNT = 256;

struct UtlTsHash {
    UtlMemoryPool   entry_mem;                              // 0x0000
    UtlTsHashBucket buckets[UTL_TS_HASH_BUCKET_COUNT];     // 0x0060
    // 0x0060 + 256*24 = 0x1860
    uint8_t  needs_commit;       // 0x1860
    uint8_t  pad_0[0x3];        // 0x1861
    int32_t  contention_check;   // 0x1864
    uint8_t  pad_1[0x8];        // 0x1868
};

static_assert(offsetof(UtlTsHash, buckets) == 0x0060);
static_assert(sizeof(UtlTsHash) == 0x1870);

// ============================================================
// tier1 — UtlVector (embedded, for SchemaSystem.type_scopes)
// ============================================================

struct UtlVector {
    int32_t  count;     // 0x0000
    uint8_t  pad_0[4];  // 0x0004
    uint64_t data;       // 0x0008 — ptr to array of elements
};

static_assert(sizeof(UtlVector) == 0x0010);

// ============================================================
// schema_system — SchemaSystem
// ============================================================

struct SchemaSystem {
    uint8_t   pad_0[0x190];         // 0x0000
    UtlVector type_scopes;          // 0x0190 — UtlVector<Pointer64<SchemaSystemTypeScope>>
    uint8_t   pad_1[0xE0];         // 0x01A0
    int32_t   registration_count;   // 0x0280
};

static_assert(offsetof(SchemaSystem, type_scopes)       == 0x0190);
static_assert(offsetof(SchemaSystem, registration_count) == 0x0280);

// ============================================================
// schema_system — SchemaSystemTypeScope
// ============================================================

struct SchemaSystemTypeScope {
    uint8_t     pad_0[0x8];                 // 0x0000
    char        name[256];                  // 0x0008
    uint64_t    global_scope;               // 0x0108 — ptr to SchemaSystemTypeScope
    uint8_t     pad_1[0x450];              // 0x0110
    UtlTsHash   class_bindings;             // 0x0560
    UtlTsHash   enum_bindings;              // 0x1DD0
};

static_assert(offsetof(SchemaSystemTypeScope, name)           == 0x0008);
static_assert(offsetof(SchemaSystemTypeScope, class_bindings) == 0x0560);
static_assert(offsetof(SchemaSystemTypeScope, enum_bindings)  == 0x1DD0);

// ============================================================
// schema_system — SchemaClassInfoData (= SchemaClassBinding)
// ============================================================

struct SchemaClassInfoData {
    uint64_t base;                    // 0x0000 — ptr to self
    uint64_t name;                    // 0x0008 — ptr to string
    uint64_t binary_name;             // 0x0010 — ptr to string
    uint64_t module_name;             // 0x0018 — ptr to string
    int32_t  size;                    // 0x0020
    int16_t  field_count;             // 0x0024
    int16_t  static_metadata_count;   // 0x0026
    uint8_t  pad_0[0x2];             // 0x0028
    uint8_t  alignment;               // 0x002A
    uint8_t  has_base_class;          // 0x002B
    int16_t  total_class_size;        // 0x002C
    int16_t  derived_class_size;      // 0x002E
    uint64_t fields;                  // 0x0030 — ptr to SchemaClassFieldData[]
    uint8_t  pad_1[0x8];             // 0x0038
    uint64_t base_classes;            // 0x0040 — ptr to SchemaBaseClassInfoData
    uint64_t static_metadata;         // 0x0048 — ptr to SchemaMetadataEntryData[]
    uint8_t  pad_2[0x8];             // 0x0050
    uint64_t type_scope;              // 0x0058 — ptr to SchemaSystemTypeScope
    uint64_t type_ptr;                // 0x0060 — ptr to SchemaType
    uint8_t  pad_3[0x10];            // 0x0068
};

static_assert(offsetof(SchemaClassInfoData, name)                   == 0x0008);
static_assert(offsetof(SchemaClassInfoData, module_name)            == 0x0018);
static_assert(offsetof(SchemaClassInfoData, field_count)            == 0x0024);
static_assert(offsetof(SchemaClassInfoData, static_metadata_count)  == 0x0026);
static_assert(offsetof(SchemaClassInfoData, fields)                 == 0x0030);
static_assert(offsetof(SchemaClassInfoData, base_classes)           == 0x0040);
static_assert(offsetof(SchemaClassInfoData, static_metadata)        == 0x0048);
static_assert(offsetof(SchemaClassInfoData, type_scope)             == 0x0058);
static_assert(sizeof(SchemaClassInfoData) == 0x0078);

using SchemaClassBinding = SchemaClassInfoData;

// ============================================================
// schema_system — SchemaClassFieldData
// ============================================================

struct SchemaClassFieldData {
    uint64_t name;              // 0x0000 — ptr to string
    uint64_t type_ptr;          // 0x0008 — ptr to SchemaType
    int32_t  offset;            // 0x0010
    int32_t  metadata_count;    // 0x0014
    uint64_t metadata;          // 0x0018 — ptr to SchemaMetadataEntryData
};

static_assert(sizeof(SchemaClassFieldData) == 0x0020);

// ============================================================
// schema_system — SchemaBaseClassInfoData
// ============================================================

struct SchemaBaseClassInfoData {
    uint8_t  pad_0[0x18];       // 0x0000
    uint64_t class_ptr;         // 0x0018 — ptr to SchemaBaseClass
};

static_assert(sizeof(SchemaBaseClassInfoData) == 0x0020);

struct SchemaBaseClass {
    uint8_t  pad_0[0x10];       // 0x0000
    uint64_t name;              // 0x0010 — ptr to string
};

static_assert(sizeof(SchemaBaseClass) == 0x0018);

// ============================================================
// schema_system — SchemaEnumInfoData (= SchemaEnumBinding)
// ============================================================

struct SchemaEnumInfoData {
    uint64_t base;                      // 0x0000
    uint64_t name;                      // 0x0008 — ptr to string
    uint64_t module_name;               // 0x0010 — ptr to string
    uint8_t  size;                      // 0x0018
    uint8_t  alignment;                 // 0x0019
    uint8_t  flags;                     // 0x001A
    uint8_t  pad_0[0x1];              // 0x001B
    uint16_t enumerator_count;          // 0x001C
    uint16_t static_metadata_count;     // 0x001E
    uint64_t enumerators;               // 0x0020 — ptr to SchemaEnumeratorInfoData[]
    uint64_t static_metadata;           // 0x0028
    uint64_t type_scope;                // 0x0030
    int64_t  min_enumerator_value;      // 0x0038
    int64_t  max_enumerator_value;      // 0x0040
};

static_assert(sizeof(SchemaEnumInfoData) == 0x0048);

using SchemaEnumBinding = SchemaEnumInfoData;

// ============================================================
// schema_system — SchemaEnumeratorInfoData
// ============================================================

struct SchemaEnumeratorInfoData {
    uint64_t name;              // 0x0000 — ptr to string
    uint64_t value;             // 0x0008 — union { u8, u16, u32, u64 }
    int32_t  metadata_count;    // 0x0010
    uint8_t  pad_0[0x4];      // 0x0014
    uint64_t metadata;          // 0x0018
};

static_assert(sizeof(SchemaEnumeratorInfoData) == 0x0020);

// ============================================================
// schema_system — SchemaMetadataEntryData
// ============================================================

struct SchemaVarName {
    uint64_t name;          // 0x0000 — ptr to string
    uint64_t type_name;     // 0x0008 — ptr to string
};

struct SchemaMetadataEntryData {
    uint64_t name;              // 0x0000 — ptr to string
    uint64_t network_value;     // 0x0008 — ptr to SchemaNetworkValue
};

static_assert(sizeof(SchemaMetadataEntryData) == 0x0010);

// SchemaNetworkValue: the value union starts at offset 0
// We read 32 bytes to cover all union variants.
struct SchemaNetworkValue {
    union {
        uint64_t     name_ptr;       // ptr to string
        int32_t      int_value;
        float        float_value;
        uint64_t     ptr_value;
        SchemaVarName var_value;
        char          name_value[32];
    } value; // 0x0000
};

// ============================================================
// schema_system — SchemaType (minimal, we only need the name)
// ============================================================

struct SchemaType {
    uint8_t  pad_0[0x8];    // 0x0000
    uint64_t name;          // 0x0008 — ptr to string
};

#pragma pack(pop)
