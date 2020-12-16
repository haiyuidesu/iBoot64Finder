#define _GNU_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

int length = 0;
bool paced = 0;
void *ibot = NULL;
uint64_t base = 0;
uint32_t version = 0;
uint64_t _print = 0, insn = 0;

// Thank you @b1n4r1b01 and @xerub !

#define bswap32(x) __builtin_bswap32(x)

#define hex_set(vers, hex1, hex2) ((version < vers) ? hex1 : hex2)

uint64_t xref64(uint64_t start, uint64_t what) {
  uint64_t i;
  uint64_t value[32];

  memset(value, 0, sizeof(value));

  uint64_t end = length;

  end &= ~0x3;

  for (i = start & ~0x3; i < end; i += 0x4) {
    uint32_t op = *(uint32_t*)(ibot + i);
    unsigned reg = op & 0x1f;

    if ((op & 0x9f000000) == 0x90000000) {
      signed adr = ((op & 0x60000000) >> 0x12) | ((op & 0xffffe0) << 8);
      value[reg] = ((long long) adr << 1) + (i & ~0xfff);
    } else if ((op & 0xff000000) == 0x91000000) {
      unsigned rn = (op >> 0x5) & 0x1f;
    if (rn == 0x1f) {
      value[reg] = 0;
      continue;
    }

    unsigned shift = (op >> 0x16) & 0x3;
    unsigned imm = (op >> 0xA) & 0xfff;

    if (shift == 1) {
      imm <<= 0xC;
    } else {
      if (shift > 1) continue;
    }

    value[reg] = value[rn] + imm;
  } else if ((op & 0xf9C00000) == 0xf9400000) {
    unsigned rn = (op >> 0x5) & 0x1f;
    unsigned imm = ((op >> 0xA) & 0xfff) << 0x3;
    if (!imm) continue;
    value[reg] = value[rn] + imm;
  } else if ((op & 0x9f000000) == 0x10000000) {
    signed adr = ((op & 0x60000000) >> 0x12) | ((op & 0xffffe0) << 8);
    value[reg] = ((long long)adr >> 0xB) + i;
  } else if ((op & 0xff000000) == 0x58000000) {
    unsigned adr = (op & 0xffffe0) >> 3;
    value[reg] = adr + i;
  } else if ((op & 0xFC000000) == 0x94000000) {
    // BL addr
    signed imm = (op & 0x3ffffff) << 2;
    if (op & 0x2000000) {
      imm |= 0xf << 0x1c;
    }
    unsigned adr = (unsigned)(i + imm);
    if (adr == what) {
      return i;
    }
  }
  if (value[reg] == what && reg != 0x1f) return i;
}

return 0;
}

uint64_t bof64(uint64_t start, uint64_t where) {
  for (; where >= start; where -= 0x4) {
    uint32_t op = *(uint32_t *)(ibot + where);
    
    if ((op & 0xffc003ff) == 0x910003fd) {
      unsigned delta = (op >> 10) & 0xfff;
      
      if ((delta & 0xf) == 0) {
        uint64_t prev = where - ((delta >> 0x4) + 1) * 0x4;

        uint32_t au = *(uint32_t *)(ibot + prev);

        if ((au & 0xffc003e0) == 0xa98003e0) return prev;

        while (where > start) {
          where -= 0x4;

          au = *(uint32_t *)(ibot + where);

          if ((au & 0xffc003ff) == 0xd10003ff && ((au >> 10) & 0xfff) == delta + 0x10)
            return where;
          
          if ((au & 0xffc003e0) != 0xa90003e0) {
            where += 0x4;
            break;
          }
        }
      }
    }
  }
    
  return 0;
}

bool detect_pac(void) {
  const uint8_t pac_insn[] = { 0x7f, 0x23, 0x03, 0xd5 };

  void *pac_search = memmem(ibot, length, pac_insn, 0x4);

  if (pac_search) return (paced = true);
  
  return (paced = false);
}

uint64_t find_b_l_insn(uint64_t xref, int x, int ins) {
  for (int i = 0; i < x; i++) {
    xref += 0x4;

    if (ins == 1) {
      while (*(uint32_t *)(ibot + xref) >> 0x1a != 0x25) xref += 0x4;
      // BL instructions (jumps into another subroutine and returns the result in the LR register)
    } else {
      while ((*(uint32_t *)(ibot + xref) >> 0x1a) % (1 << (0x1f - 0x1a + 1)) != 0x5) xref += 0x4;
      // B instructions (jumps into another subroutine and never come back | returns nothing)
    }
  }

  return xref;
}

uint64_t follow_call64(uint64_t call) {
  long long w;
  w = *(uint32_t *)(ibot + call) & 0x3ffffff;
  w <<= 0x40 - 0x1a;
  w >>= 0x40 - 0x1a - 0x2;
  return call + w;
}

// find_xref(insn or not, string, function name, how many BL to count, usage of bof64, finding a bl or b insn);
uint64_t find_xref(uint64_t xref, char *str, char *name, int count, bool beg, char *bx) {
  if (xref <= 0) {
    void *bl = memmem(ibot, length, str, strlen(str));

    /*if (bl == NULL) {
      printf("[%s]: %s = NULL\n", __func__, name);
      return -1;
    }*/

    xref = xref64(0x0, bl - ibot);

    /*if (xref == 0) {
      printf("[%s]: %s = NULL\n", __func__, name);
      return -1;
    }*/
  }

  if (beg == true) insn = bof64(0x0, xref);

  if (count > 0) {
    insn = (!strcmp(bx, "bl")) ? find_b_l_insn(xref, count, 1) : find_b_l_insn(xref, count, 0);

    if (!insn) {
      printf("[%s]: %s = NULL\n", __func__, name);
      return -1;
    }

    insn = follow_call64(insn);
  }

  if (_print == 0) printf("[%s]: %s = 0x%llx\n", __func__, name, insn + base);

  _print = 0;

  return insn;
}

int insn_set(uint32_t v12, uint32_t v13, uint32_t v14, uint32_t vX) {
  if (version == 4513) return (insn = v12);
  else if (version == 5540) return (insn = v13);
  else if (version >= 6603) return (insn = v14);
  else return (insn = vX);
}

void *find_func(void) {
  uint64_t img4_load = 0;

  find_xref(0x0, hex_set(5540, "Attempting to", "darwinos-ramdisk"), "_do_bootx", 0x0, true, NULL);
  find_xref(0x0, "debug-uarts",                "_main_task", 0x0, true, NULL);
  find_xref(0x0, "Combo image too",            "_do_memboot", 0x0, true, NULL);
  uint64_t use = find_xref(0x0, "mem",         "_boot_darwin", 0x8, false, "bl");
  find_xref(0x0, "usb req",                    "_event_init", 0x3, false, "bl");
  uint64_t less = find_xref(0x0, "main",       "_task_start", 0x2, false, "bl");
  find_xref(0x0, "main",                       "_task_create", 0x1, false, "bl");
  find_xref(0x0, "boot-device",                "_mount_bootfs", 0x0, true, NULL);
  find_xref(0x0, "<null>",                     "_decode_ascii", 0x1, false, "bl");
  uint64_t var = find_xref(0x0, "backlight-level", "_env_get_uint", 0x1, false, "bl");
  find_xref(0x0, "upgrade-retry",              "_env_get_bool", 0x1, false, "bl");
  find_xref(0x0, "BootArgs",                   "_record_memory_range", 0x1, false, "bl");
  find_xref(0x0, "mem",                        "_create_mem_blockdev", 0x1, false, "bl");
  find_xref(0x0, "boot-path",                  "_mount_and_boot_system", 0x0, true, NULL);

  find_xref(less, NULL,                        "_enter_critical_section", 0x1, false, "bl");
  find_xref(less, NULL,                        "_exit_critical_section", hex_set(5540, 0x1, 0x2), false, "b");

  find_xref(0x0, "BootArgs",                   "_alloc_kernel_mem", 0x5, false, "bl");
  var = find_xref(var, NULL,                   "_read_nvram_check", 0x1, false, "bl");

  uint64_t usb = find_xref(0x0, "Apple Mobile Device (Recovery Mode)", "_usb_core_init", 0x1, false, "bl");
  find_xref(0x0, "Apple Mobile Device (Recovery Mode)", "_usb_core_start", 0x4, false, "bl");
  find_xref(usb, NULL,                         "_usb_create_string_descriptor", 0x7, false, "bl");
  
  var = find_xref(var, NULL,                   "_check_data_at_heap_const", 0x1, false, "bl");
  find_xref(0x0, "pram",                       "_dt_find_node_with_name", 0x1, false, "bl");
  find_xref(0x0, "boot-device",                "_verify_heap_checksum", 0x5, false, "bl");
  find_xref(0x0, "diags-path",                 "_boot_diagnostics_fs", 0x0, true, NULL);
  find_xref(0x0, "debug=",                     "_contains_boot_arg", 0x1, false, "bl");
  uint64_t name = find_xref(0x0, "/boot/iBEC", "_prepare_and_jump", hex_set(5540, 0x4, 0x5), false, "bl");
  find_xref(0x0, "debug-enabled",              "_UpdateDeviceTree", 0x0, true, NULL);
  find_xref(0x0, "Memory image not valid",     "_boot_object", 0x4, false, "bl");

  find_xref(name, NULL,                        "_platform_bootprep", hex_set(5540, 0x3, 0x6), false, "bl");
  less = find_xref(0x0, "effective-security",  "_platform_get_nonce", hex_set(5540, 0x4, 0x5), false, "bl");
  find_xref(less, NULL,                        "_platform_read_nonce", 0x1, false, "bl");

  if (version < 6603) find_xref(0x0, "backlight-level", "_platform_init_display", 0x0, true, NULL);

  find_xref(name, NULL,                        "_platform_quiesce_hardware", hex_set(5540, 0x4, 0x7), false, "bl");
  var = find_xref(0x0, hex_set(5540, "CPID:", "SDOM:"), "_platform_get_usb_serial_number_string", 0x0, true, NULL);

  _print = 1;  // for some reasons find_xref() did not worked properly here so here it will stay.
  uint64_t ref_b = find_xref(var, NULL,        "_useless_function", hex_set(5540, 0x1, 0x2), false, "bl");
  printf("[%s]: %s = 0x%llx\n", __func__,      "_platform_get_chip_id", follow_call64(ref_b) + base);
  
  _print = 1; // In fact I knew why but the code would be more ugly than it currently is, so here it will stay.
  ref_b = find_xref(var, NULL,                 "_useless_function", hex_set(5540, 0x2, 0x3), false, "bl");
  printf("[%s]: %s = 0x%llx\n", __func__,      "_platform_get_chip_revision", follow_call64(ref_b) + base);

  find_xref(var, NULL,                         "_platform_get_fuse_modes", hex_set(5540, 0x3, 0x4), false, "bl");
  find_xref(var, NULL,                         "_platform_get_security_epoch", hex_set(5540, 0x4, 0x5), false, "bl");
  find_xref(var, NULL,                         "_platform_get_board_id", hex_set(5540, 0x5, 0x6), false, "bl");
  find_xref(var, NULL,                         "_platform_get_ecid_id", hex_set(5540, 0x6, 0x7), false, "bl");
  var = find_xref(var, NULL,                   "_platform_get_iboot_flags", hex_set(5540, 0x7, 0x8), false, "bl");
  find_xref(var, NULL,                         "_platform_get_secure_mode", 0x2, false, "bl");
  find_xref(var, NULL,                         "_platform_get_current_production_mode", 0x3, false, "bl");
  var = find_xref(0x0, " NONC:",               "_platform_get_usb_more_other_string", 0x0, true, NULL);
  find_xref(usb, NULL,                         "_platform_get_usb_vendor_id", 0x3, false, "bl");
  less = find_xref(usb, NULL,                  "_platform_get_usb_product_id", 0x4, false, "bl");
  find_xref(less, NULL,                        "_platform_get_security_domain", 0x2, false, "bl");
  find_xref(usb, NULL,                         "_platform_get_usb_device_version", 0x5, false, "bl");
  find_xref(usb, NULL,                         "_platform_get_usb_manufacturer_string", 0x6, false, "bl");
  find_xref(usb, NULL,                         "_platform_get_usb_product_string", 0x8, false, "bl");
  find_xref(var, NULL,                         "_platform_get_sep_nonce", 0x6, false, "bl");

  find_xref(0x0, "Kernelcache too large",      "_load_kernelcache_object", 0x0, true, NULL);
  less = find_xref(0x0, "/boot/kernelcache",   "_load_kernelcache_file", 0x1, false, "bl");
  find_xref(0x0, "boot-path",                  "_load_ramdisk_file", 0x8, false, "bl");
  find_xref(0x0, "Kernel-",                    "_load_kernelcache", 0x0, true, NULL);
  find_xref(0x0, "mem",                        "_load_ramdisk", 0x5, false, "bl");

  insn_set(0x1, 0x1, (detect_pac() ? 0x3 : 0x2), 0x1);
  use = find_xref(0x0, "Kernelcache too large", "_image_load_memory", insn, false, "bl");

  name = find_xref(use, NULL,                  "_image_create_from_memory", hex_set(6603, 0x1, 0x2), false, "bl");

  find_xref(0x0, "IMG4",                       "_image4_get_partial", 0x0, true, NULL);
  find_xref(0x0, "mem",                        "_image_search_bdev", 0x2, false, "bl");
  find_xref(0x0, "image %",                    "_image4_dump_list", 0x0, true, NULL);
  find_xref(0x0, "mem",                        "_image_dump_list", 0x3, false, "bl");

  insn_set(0x1, 0x2, (paced ? 0x4 : 0x2), 0x1);
  uint64_t last = find_xref(less, NULL,        "_image_load_file", insn, false, "bl");

  if (version == 5540) {
    _print = 1; // I hate to have to do that kind of bad trick...
    img4_load = find_xref(use, NULL, "_useless_function", 0x2, false, "bl");
  }

  insn_set(0x2, 0x1, (paced ? 0x7 : 0x3), 0x2);

  img4_load = find_xref((version == 5540 ? img4_load : use), NULL, "_image_load", insn, false, (version == 5540 ? "b" : "bl"));

  insn_set(0x8, 0x10, (paced ? 0x16 : 0xC), 0x8);
  img4_load = find_xref(img4_load, NULL,       "_image4_load", hex_set(4076, 0xA, insn), false, "bl");

  find_xref(use, NULL,                         "_image_free", 0x3, false, "bl");
  find_xref(0x0, "mem",                        "_image_find", 0x6, false, "bl");
  use = find_xref(0x0, "mem",                  "_image_search_bdev", 0x2, false, "bl");
  find_xref(use, NULL,                         "_image_process_superblock", hex_set(5540, 0x2, 0x3), false, "bl");

  insn_set(0x16, 0x1f, (paced ? 0x31 : 0x1e), 0x12);
  use = find_xref(img4_load, NULL,             "_Img4DecodeInit", hex_set(4076, 0x15, insn), false, "bl");

  find_xref(img4_load, NULL,                   "_Img4DecodeGetPayload", insn_set(0x21, 0x21, 0x2a, 0x1f), false, "bl");

  find_xref(img4_load, NULL,                   "_Img4DecodeManifestExists", insn_set(0x18, 0x18, 0x21, 0x17), false, "bl");
  find_xref(use, NULL,                         "_DERImg4Decode", hex_set(5540, 0x2, 0x1), false, "bl");
  find_xref(use, NULL,                         "_DERImg4DecodePayload", hex_set(5540, 0x3, 0x2), false, "bl");
  find_xref(use, NULL,                         "_DERImg4DecodeManifest", hex_set(5540, 0x4, 0x3), false, "bl");
  use = find_xref(use, NULL,                   "_DERImg4DecodeRestoreInfo", hex_set(5540, 0x5, 0x4), false, "bl");
  find_xref(use, NULL,                         "_DERImg4DecodeTagCompare", 0x2, false, "bl");
  use = find_xref(use, NULL,                   "_DERParseSequence", 0x1, false, "bl");
  find_xref(use, NULL,                         "_DERDecodeItemPartialBufferGetLength", 0x1, false, "bl");
  find_xref(use, NULL,                         "_DERParseSequenceContent", 0x2, false, "bl");

  find_xref(last, NULL,                        "_fs_load_file", 0x1, false, "bl");
  find_xref(var, NULL,                         "_hash_calculate", hex_set(5540, 0x2, 0x3), false, "bl");

  less = find_xref(0x0, (version >= 6603 ? "idleoff" : "BootArgs"), "_security_init", insn_set(0x12, 0x18, 0xD, 0x16), false, "bl");

  find_xref(0x0, "debug-enabled",              "_security_allow_modes", 0x2, false, "bl");
  find_xref(0x0, "Combo image too large",      "_security_allow_memory", 0x1, false, "bl");
  find_xref(less, NULL,                        "_security_protect_memory", hex_set(4513, 0x6, 0x7), false, "bl");
  find_xref(less, NULL,                        "_security_clear_memory_in_chunks", hex_set(5540, 0x5, 0xA), false, "bl");

  find_xref(0x0, "<ptr>",                      "_do_printf", 0x0, true, NULL);
  find_xref(0x0, "Kernel-",                    "_snprintf", 0x2, false, "bl");
  find_xref(usb, NULL,                         "_memalign", 0xE, false, "bl");
  find_xref(0x0, " SRNM:",                     "_strlcpy", 0x1, false, "bl");
  find_xref(0x0, " SRNM:",                     "_strlcat", 0x3, false, "bl");
  find_xref(usb, NULL,                         "_memset", 0xf, false, "bl");
  find_xref(0x0, "macaddr/",                   "_memcmp", 0x1, false, "bl");
  find_xref(0x0, "network-type",               "_strcmp", 0x2, false, "bl");
  find_xref(0x0, "zeroes/",                    "_strsep", 0x3, false, "bl");
  find_xref(0x0, "zeroes/",                    "_strlen", 0x4, false, "bl");
  find_xref(name, NULL,                        "_malloc", 0x1, false, "bl");
  find_xref(0x0, "effective-security",         "_memcpy", hex_set(5540, 0x5, 0x7), false, "bl");
  find_xref(0x0, "Entering recovery mode",     "_printf", 0x1, false, "bl");
  last = find_xref(0x0, "image-version",       "_free", 0x2, false, "bl");
  find_xref(last, NULL,                        "_bzero", 0x5, false, "bl");
  find_xref(0x0, hex_set(6603, "double panic in ", "iBoot Panic"), "_panic", 0x0, true, NULL);

  return ibot;
}

void usage(char *owo[]) {
  char *ibot = NULL;
  ibot = strrchr(owo[0], '/');
  printf("usage: %s [-f] <iboot>\n", ibot ? ibot + 1 : owo[0]);
  printf("\t-f, --find\tfind some functions of a decrypted iBoot64.\n");
}

int main(int argc, char *argv[]) {
  int find = 0;
  FILE *fd = NULL;

  if (argc < 3) goto usagend;

  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "-f") || !strcmp(argv[i], "--find")) {
      find = 1;
      break;
    } else {
      printf("warning: unrecognized argument: %s\n", argv[i]);
      goto usagend;
    }
  }

  if (find) {
    printf("[%s]: starting..\n", __func__);
    
    fd = fopen(argv[2], "rb");

    if (!fd) {
      printf("[%s]: unable to open %s.\n", __func__, argv[2]);
      return -1;
    }

    fseek(fd, 0x0, SEEK_END);
    
    length = ftell(fd);
    
    fseek(fd, 0x0, SEEK_SET);
    
    ibot = (void *)malloc(length);
    
    fread(ibot, 1, length, fd);
    
    fflush(fd);
    fclose(fd);

    if (*(uint32_t *)ibot == 0x496d6733) {
      printf("[%s]: IMG3 files are not supported.\n", __func__);
      goto end;
    }

    if (*(uint32_t *)ibot != 0xea00000e && *(uint32_t *)ibot != 0x90000000) {
      printf("[%s]: this is not a valid iBoot64 image.\n", __func__);
      goto end;
    }

    if (detect_pac() == true) {
      printf("[%s]: PACed iBoot detected!\n", __func__);
    }

    printf("[%s]: detected iBoot-%s!\n", __func__, ibot + 0x286);

    version = atoi(ibot + 0x286);

    if (version <= 2817) {
      printf("[%s]: iBoot64Finder support for now iOS 10 to iOS 14.\n", __func__);
      goto end;
    }

    base = *(uint64_t *)(ibot + hex_set(6603, 0x318, 0x300));

    printf("[%s]: base_addr = 0x%llx\n", __func__, base);

    if (!find_func()) return -1;

    printf("[%s]: done!\n", __func__);

    return 0;
  }

  usagend:
  usage(argv);
  return -1;

  end:
  free(ibot);
  return -1;
}