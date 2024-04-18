
static __always_inline mapping_t* find_mapping(int per_process_id, u64 pc) {
  struct exec_mappings_key key = {};
  key.prefix_len = PREFIX_LEN;
  key.pid = __builtin_bswap32((u32) per_process_id);
  key.data = __builtin_bswap64(pc);

  mapping_t *mapping = bpf_map_lookup_elem(&exec_mappings, &key);

  if (mapping == NULL) {
    LOG("[error] no mapping found for pc %llx", pc);
    bump_unwind_error_mapping_not_found();
    return NULL;
  }

  if (pc < mapping->begin || pc >= mapping->end) {
    LOG("[error] pc %llx not contained within begin: %llx end: %llx", pc, mapping->begin, mapping->end);
    bump_unwind_error_mapping_does_not_contain_pc();
    return NULL;
  }

  return mapping;
}

static __always_inline bool process_is_known(int per_process_id) {
  struct exec_mappings_key key = {};
  key.prefix_len = PREFIX_LEN;
  key.pid = __builtin_bswap32((u32) per_process_id);
  key.data = 0;

  return bpf_map_lookup_elem(&exec_mappings, &key) != NULL;
}