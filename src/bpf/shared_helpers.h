
static __always_inline mapping_t* find_mapping(int per_process_id, u64 pc) {
  struct exec_mappings_key key = {};
  key.prefix_len = PREFIX_LEN;
  key.pid = __builtin_bswap32((u32) per_process_id);
  key.data = __builtin_bswap64(pc);

  return bpf_map_lookup_elem(&exec_mappings, &key);
}

static __always_inline bool process_is_known(int per_process_id) {
  struct exec_mappings_key key = {};
  key.prefix_len = PREFIX_LEN;
  key.pid = __builtin_bswap32((u32) per_process_id);
  key.data = 0;

  return bpf_map_lookup_elem(&exec_mappings, &key) != NULL;
}