#ifndef LIGHTSWITCH_UNWIND_RULES_H
#define LIGHTSWITCH_UNWIND_RULES_H

// Included after profiler.h and bpf_helpers.h. These decoders mirror the
// checked encodings in lightswitch-unwind-info without widening the 8-byte row.
static __always_inline bool decode_cfa_deref(u8 type, u16 operands,
                                            s16* offset, u16* addition, u8* size) {
    if (type < CFA_TYPE_DEREF_AND_ADD || type > CFA_TYPE_DEREF_AND_ADD + 11)
        return false;

    u8 mode = type & 12;
    *offset = mode == 0 ? (s16)(operands >> 8) : (s16)(s8)(operands >> 8);
    *addition = (u8)operands;
    if (mode == 8) {
        *offset *= 8;
        *addition *= 8;
    }
    u8 width = type & 3;
    *size = width == 0 ? 8 : (1 << (width - 1));
    return true;
}

static __always_inline int read_cfa_deref(u64 sp, s16 offset, u16 addition,
                                         u8 size, u64* cfa) {
    void* address = (void*)(sp + offset);
    int err;
    // Use the declared load width, including near the end of a readable page.
    // Reading eight bytes then masking could fault or access unrelated memory.
    if (size == 1) {
        u8 value = 0;
        err = bpf_probe_read_user(&value, sizeof(value), address);
        *cfa = value;
    } else if (size == 2) {
        u16 value = 0;
        err = bpf_probe_read_user(&value, sizeof(value), address);
        *cfa = value;
    } else if (size == 4) {
        u32 value = 0;
        err = bpf_probe_read_user(&value, sizeof(value), address);
        *cfa = value;
    } else if (size == 8) {
        u64 value = 0;
        err = bpf_probe_read_user(&value, sizeof(value), address);
        *cfa = value;
    } else {
        return -22; // EINVAL
    }
    if (err < 0)
        return err;
    *cfa += addition;
    return 0;
}

struct register_rules {
    s32 fp_offset;
    s32 ra_offset;
    bool restore_fp;
    bool use_lr;
};

static __always_inline bool decode_register_rules(u8 type, s16 operands,
                                                  bool arm64, struct register_rules* rules) {
    rules->fp_offset = operands;
    rules->ra_offset = -8;
    rules->restore_fp = false;
    rules->use_lr = false;

    if (!arm64) {
        if (type == RBP_TYPE_UNCHANGED)
            return true;
        if (type == RBP_TYPE_OFFSET) {
            rules->restore_fp = true;
            return true;
        }
        return false;
    }

    switch (type) {
    case RBP_TYPE_ARM64_RETURN_ADDRESS_LR:
        rules->use_lr = true;
        return true;
    case RBP_TYPE_ARM64_RETURN_ADDRESS_LR_WITH_FP:
        rules->restore_fp = true;
        rules->use_lr = true;
        return true;
    case RBP_TYPE_ARM64_RETURN_ADDRESS_FRAME:
        rules->restore_fp = true;
        rules->ra_offset = (s32)operands + 8;
        return true;
    case RBP_TYPE_ARM64_RETURN_ADDRESS_ELSEWHERE:
        rules->ra_offset = operands;
        return true;
    case RBP_TYPE_ARM64_INDEPENDENT_OFFSETS:
    case RBP_TYPE_ARM64_INDEPENDENT_OFFSETS_SCALED:
        rules->restore_fp = true;
        rules->fp_offset = (s8)((u16)operands >> 8);
        rules->ra_offset = (s8)operands;
        if (type == RBP_TYPE_ARM64_INDEPENDENT_OFFSETS_SCALED) {
            rules->fp_offset *= 8;
            rules->ra_offset *= 8;
        }
        return true;
    default:
        return false;
    }
}

#endif
