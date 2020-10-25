#define _GNU_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

int length = 0;
void *ibot = NULL;
uint64_t base = 0;
uint32_t version = 0;
uint64_t insn = 0, _insn = 0;

// Thank you @b1n4r1b01 and @xerub !

#define bswap32(x) __builtin_bswap32(x)

#define hex_set(vers, hex1, hex2) ((version < vers) ? hex1 : hex2)

uint64_t bof64(const void *buf, uint64_t start, uint64_t where) {
  for (; where >= start; where -= 0x4) {
    uint32_t op = *(uint32_t *)(buf + where);
    
    if ((op & 0xffc003ff) == 0x910003fd) {
      unsigned delta = (op >> 10) & 0xfff;
      
      if ((delta & 0xf) == 0) {
        uint64_t prev = where - ((delta >> 0x4) + 1) * 0x4;

        uint32_t au = *(uint32_t *)(buf + prev);

        if ((au & 0xffc003e0) == 0xa98003e0) return prev;

        while (where > start) {
          where -= 0x4;

          au = *(uint32_t *)(buf + where);

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

void *find_insn_before_ptr(void *ptr, uint32_t search, int size) {
  int ct = 0;

  while (size) {
    uint32_t insn = *(uint32_t *)(ptr - ct);

    if (insn == search) return (ptr - ct + 0x4);

    size -= 0x4;
    ct += 0x4;
  }

  return NULL;
}

void *memdata(uint64_t data, int data_size, void *last_ptr) {
  int loc = length - (ibot - last_ptr);
 
  void *ptr = (void *)memmem(last_ptr + 0x4, loc - 0x4, (const char *)&data, data_size);
  
  if (ptr) return ptr;
 
  return NULL;
}

bool detect_pac(void) {
  void *pac_search = memdata(bswap32(0x7f2303d5), 0x4, ibot);

  if (pac_search) return true;
  
  return false;
}
 
uint64_t locate_func(uint32_t insn, uint32_t _insn, bool x, char *func) {
  uint64_t beg = 0, loc = 0;

  void *first_occur = ibot;
  
  while (first_occur > 0) {
    first_occur = memdata(bswap32(insn), 0x4, first_occur);
    
    if (first_occur && find_insn_before_ptr(first_occur, bswap32(_insn), 0x200)) {
      loc = (uint64_t)((uintptr_t)first_occur - (uintptr_t)ibot);
 
      if (x == 0) beg = bof64(ibot, 0x0, loc); // Functions with prologues

      if (detect_pac() == true) beg -= 0x4;
 
      printf("[%s]: %s = 0x%llx\n", __func__, func, (base + (x ? loc : beg)));
 
      return beg;
    }
  }
 
  return 0;
}

/* iOS 7 | iOS 8 | iOS 9 | iOS 13 ~ 14 | iOS 10 to 12 */
#define insn_set(x, vers1, vers2, vers3, vers4, vers5) \
if      (version == 1940) x = vers1; \
else if (version == 2261) x = vers2; \
else if (version == 2817) x = vers3; \
else if (version >= 5540) x = vers4; \
else                      x = vers5;

// I basically wrote this for the DTK iBoot but... I am lost...
#define pac_condition(hex1, hex2) ((detect_pac() && version >= 6603) ? hex1 : hex2)

// https://armconverter.com/ (If you ever try to translate every offsets here, I will give you a cola).

void find_image(void) {
  locate_func(hex_set(4076, hex_set(3406, 0x89e68c72, 0xc0008072), 0x6000a872), 
    hex_set(4076, hex_set(3406, 0x080c40b9, 0x6000a852), 0xc0008052), false, "_image_load");

  locate_func(0x09090253,
    hex_set(2817, 0x010a80d2, hex_set(4076, 0x020a8052, 0xe803002a)), false, "_image4_load");

  locate_func(0x6082813c, hex_set(2817, 0x61220591, 0xc0c20091), false, "_Img4DecodeInit");

  locate_func(hex_set(4013, hex_set(3406, 0xe20318aa, 0x48af8d72), 0x6000a872), 
    hex_set(4013, hex_set(3406, 0x810240f9, 0x010b40b9), 0x80018052), false, "_image_load_file");


  insn_set(insn, 
    0x2a5d1053, 0x0a5d1053, 0x0a5d1053, 
    hex_set(6603, 0x2b5d1053, 0x09294429), 0x2b5d1053);
  locate_func(0xe00313aa, insn, false, "_image4_dump_list");

  locate_func(hex_set(5540, 0x1f000871, 0x03408052),
    hex_set(5540, 0x00013fd6, 0x01088052), false, "_image_search_bdev");

  locate_func(hex_set(3406, 0xe20307aa, 0xf40307aa),
    hex_set(3406, 0xf30306aa, 0xfd030191), false, "_image_load_memory");


  locate_func(hex_set(3406, 0x0100e4d2, 0xf5030091), 0xf30302aa, false, "_image4_get_partial");

  locate_func(0x8082c93c, 0xe00314aa, false, "_Img4DecodeGetPayload");

  locate_func(hex_set(3406, 0x08cc0129, 0x084c0129),
    hex_set(4076, 0x48af8d72, 0xa8aca972), false, "_image_create_from_memory");

  insn_set(insn,
    0x0841298b, 0x6931899a, 0x6931899a, 0x6832881a, 0x20013fd6);
  insn_set(_insn,
    0xea279f1a, 0x2b0840b9, 0x2b0840b9, 0x7f7a00f1, 0xc91640f9);
  locate_func(insn, _insn, false, "_image4_process_superblock");

  locate_func(0xe30313aa, hex_set(2817, hex_set(2261, 0xe822c89a, 0x6823c99a), 0xe822c99a), 0,
    "_Img4DecodeEvaluateDictionaryProperties");

  locate_func(0x1f0500f1, 0x210843b2, false, "_Img4DecodeGetPropertyBoolean");

  locate_func(0x1f1100f1, 0x210843b2, false, "_Img4DecodeGetPropertyData");

  locate_func(hex_set(3406, 0x29000039, 0x28000039),
    hex_set(3406, 0x090c40f9, 0x080d40f9), true, "_Img4DecodeManifestExists");
}

void find_libc(void) {
  insn_set(insn,
    0x2a3140a9, 0x2a3140a9, 0xb81a088b, 0x29195a8b, 0x2a0908cb);
  locate_func(hex_set(2817, 0x4ae57a92, 0x2a0540b3), insn, false, "_memalign");

  locate_func(0xbfae0071, 0xf60302aa, false, "_strtoull");

  locate_func(hex_set(2817, 0x0a1d0012, 0x091d0012), 0x28004039, true, "_strncmp");

  locate_func(0x0809C19a, 0x08008012, true, "_calloc");

  locate_func(0x1f01216b, 0x08004039, true, "_strchr");

  locate_func(hex_set(3406, 0x29054039, 0x000500d1),
    hex_set(3406, 0x0901008b, 0x09686838), true, "_strlen");
  
  if (version >= 2817) locate_func(0x8c050091, 0x8d014039, true, "_strsep");

  insn_set(insn, 
    0x09fd46d3, 0x09fd46d3, 0x6be57ad3, 0xc81240f9, 0xc81240f9);
  insn_set(_insn, 
    0xf30300aa, 0xf30300aa, 0xab1240f9, 0xff7e00f1, 0xe00314aa);
  locate_func(insn, _insn, false, "_malloc");

  /* [NOTE]: _bcopy is translated to _memcpy (or _memmove). */
  locate_func(0x420400f1, 0x422000b1, false, "_memcpy");

  locate_func(0x217c039b, 0x211c4092, false, "_memset");

  locate_func(0x6300028b, 0x23740bd5, false, "_bzero");

  locate_func(hex_set(2817, 0x6be57a92, 0x29e57a92), hex_set(2817, 0x49e57ad3, 0x28e57ad3), false, "_free");
}

// This one is kind of hard...
void find_platform(void) {
  locate_func(hex_set(5540, hex_set(4513, 0x005d1053, 0x94120011), 0x287b75b8),
    hex_set(5540, hex_set(4513, 0x48c0a1f2, 0x605a36b8), 0xbf0a00f1), false, "_platform_update_device_tree");

  locate_func(hex_set(5540, 0x2879a8b8, 0x307ab0b8), 0xe00313aa, false, "_platform_quiesce_hardware");

  insn_set(insn,
    0x2011881a, 0x0011931a, 0x0011931a, 0x08011c12, 0x68021d32);
  insn_set(_insn,
    0x09011c32, 0x68021c32, 0x68021c32, 0x087c44d3, 0x1315881a);
  locate_func(insn, _insn, false, "_platform_get_iboot_flags");

  locate_func(hex_set(4513, hex_set(2817, 0x002d0c53, 0x007d1c53), 0x097d55d3), 
    hex_set(4513, 0x48c0a1f2, 0x082540b9), false, "_platform_get_memory_size"); // iOS 9 to 12 : the function is below.

  locate_func(hex_set(2817, 0xe17f40b2, 0x01008012),
    hex_set(5540, hex_set(3406, 0x680a0039, 0x68060039), 0x28008052), false, "_platform_init_display");

  locate_func(0x60024039, 0xe10313aa, false, "_platform_early_init");

  insn_set(insn,
    0x49c0a1f2, 0x08fc60d3, 0x53c0a1f2, 0x5300c0f2, 0x680240b9);
  locate_func(0x29011f32, insn, false, "_platform_get_nonce");

  locate_func(0x01190012, 0xe00313aa, false, "_platform_bootprep");

  locate_func(0x13041f33, 0x2800002a, false, "_platform_disable_keys");
}

void find_load(void) {
  insn_set(insn,
    0x0880a0f2, 0x0880a0f2, 0x0800a2f2, 0x0101c0f2, hex_set(4076, 0x1500a2f2, 0x1501c0f2));
  locate_func(insn, hex_set(2817, 0xf40300aa, 0xf40302aa), false, "_load_kernelcache_file");

  locate_func(hex_set(3406, 0x087d4093, 0xbfd20039), hex_set(4076, 0x086d1c53, 0x08ed7cd3), false, "_load_bank_partitions");

  insn_set(insn,
    0x0880a0f2, 0x0880a0f2, 0x0800a2f2, 0x0201c0f2, hex_set(4076, 0x1500a2f2, 0x1501c0f2));
  locate_func(hex_set(5540, hex_set(3406, 0x060080d2, 0x070080d2), 0x40008012), insn, false, "_load_kernelcache");

  insn_set(insn,
    0x010140f9, 0x010140f9, 0x010140f9, 0xc100a052, hex_set(4076, 0x00e08472, 0x0040a072));
  insn_set(_insn,
    0xfd030091, 0xfd430091, 0xe10313aa, 0x0040a072, 0x02008052);
  locate_func(insn, _insn, false, "_load_fs_firmware");

  locate_func(0x1f080872, 0x08000432, false, "_load_sepos"); // iOS 12+
}

void find_usb(void) {
  insn_set(insn,
    0x600a00f9, 0x600a00f9, 0x600600f9, 0x800200f9, 0x800600f9);
  locate_func(hex_set(3406, 0x60820091,
    hex_set(5540, 0x80a20091, 0x00008252)), insn, false, "_usb_serial_early_init");

  insn_set(insn, 
    0x900d40f9, 0x900d40f9, 0x4b711d53, 0x4b711d53, 0x4b711d53);
  locate_func(insn, hex_set(2817, 0x8c3140f9, 0x6a2140b9), false, "_usb_core_start");

  insn_set(insn, 
    0xa0c20191, 0xa0c20191, 0x881a40f9, 0x6100a052, 0xa01e40f9);
  locate_func(0x020080d2, insn, false, "_usb_core_init");
}

void find_der(void) {
  locate_func(0x00008012, hex_set(3406, 0x090940b9, 0x080440f9), false, "_DERImg4DecodeTagCompare");

  locate_func(hex_set(4076, 0x090280f2, 0x0900e4f2), 0xf60301aa, false, "_DERParseSequence");

  locate_func(hex_set(4513, 0xe003881a, 0x00791f53), 0xe30313aa, false, "_DERImg4Decode");

  locate_func(0x09fd60d3, 0xf30301aa, false, "_DERParseInteger");

  locate_func(0x28000039,
    hex_set(3406, hex_set(2261, 0x1ffd0371, 0x291d0012), 0x0419407a), true, "_DERParseBoolean");

  locate_func(0x08014039, 0x5f000039, true, "_DERParseBitString");

  locate_func(0x680600f9, hex_set(5540, hex_set(2261, 0x09fe9ff2, 0x08fd41d3), 0x0900e2f2), false, "_DERDecodeSeqInit");

  locate_func(hex_set(2817, 0x891240b9, 0x680200f9), hex_set(4513, 0x682640a9, 0x082440a9), false, "_DERDecodeSeqNext");

  locate_func(hex_set(4076, hex_set(3406, 0x018a8672, 0xa1898672), 0x418a8652), 0xe30313aa, false, "_DERImg4DecodePayload");

  locate_func(hex_set(4076, 0x418a8672, 0xa129a972), hex_set(3406, 0x080840b9, 0x080440f9), false, "_DERImg4DecodeRestoreInfo");

  locate_func(0x6002803d, 0x1f0114eb, false, "_DERImg4DecodeFindInSequence");
}

void find_sep(void) {
  locate_func(hex_set(5540, 0x2902a072, 0x2802a072), 0xf30300aa, false, "_sep_client_set_antireplay_size"); // A11+

  locate_func(hex_set(5540, 0x1a02a072, 0x1902a072),
    hex_set(5540, 0xe0031f32, 0xf91f8052), false, "_sep_client_get_random_data"); // A10+

  locate_func(hex_set(4076, 0xe80c8052, 0xfadf8d52), 
    hex_set(2817, 0xe0031f32, 0xf30300aa), false, "__sep_client_get_nonce");
}

void *find_funcs(int extra) {
  insn_set(insn,
    0xe20313aa, 0xe20313aa, 0xe20313aa, 0x140500b9, hex_set(4513, 0x29010032, 0x140500b9));
  insn_set(_insn,
    0xc06640b9, 0xc06640b9, 0xc06640b9, 0x880090d2, hex_set(4513, 0x29010032, 0x140500b9));
  locate_func(insn, _insn, false, "_uart_init");

  find_image();

  find_sep();

  find_platform();

  find_der();

  find_load();

  find_usb();

  if (extra) {
    locate_func(0x08054039, 0x04148052, false, "_parse_chain");

    locate_func(0x163d0012, 0x084c40f9, false, "_parse_extensions"); // iOS 10+

    locate_func(0x09fc1f38, 0x290c4092, true, "_decode_ascii");

    locate_func(hex_set(5540, 0x08008092, 0x097d00a9),
      hex_set(5540, 0x0801092a, 0x09008092), false, "_security_init");

    locate_func(hex_set(2817, 0x0001090a, 0x4001080a), 0xe8879f1a, true, "_security_allow_memory");

    locate_func(hex_set(5540, 0x09fd00a9, 0x0800018b),
      hex_set(5540, 0x09008092, 0x097d00a9), true, "_security_protect_memory");

    locate_func(hex_set(4513, hex_set(2817, 0xb482969a, 0xd582939a), 0x7502969a),
      hex_set(4513, hex_set(2817, 0xdf0215eb, 0x7f0216eb), 0x68fe5cd3), false, "_security_clear_memory_in_chunks");

    locate_func(hex_set(5540, 0x0000080a, 0x0000098a),
      0x68020052, true, "_security_get_effective_production_status");

    locate_func(  0x1fc100f1, hex_set(3406, 0xa81240f9, 0x681240f9), false, "_verify_chain_signatures"); // iOS 9+

    locate_func(0x015238d5, 0xbf4000d5, true, "_exception_vector_base");

    locate_func(0xdf3f03d5, 0x00e21bd5, true, "_write_phys_timer_ctl");

    locate_func(hex_set(3406, hex_set(2817, 0x4a050011, 0x68050011), 0x092c00b9),
      hex_set(3406, hex_set(2817, 0x5fa10f71, 0x7fa10f71), 0x09050011), false, "_enter_critical_section");

    locate_func(hex_set(3406, 0x4a050051, 0x082c00b9),
      hex_set(3406, hex_set(2817, 0x090140f9, 0x5f010071), 0x1f010071), false, "_exit_critical_section");

    locate_func(hex_set(3406, hex_set(2817, 0x29910111, 0x48910111), 0x082c00b9),
      hex_set(3406, hex_set(2817, 0x3fa10f71, 0x5fa10f71), 0x08910111), false, "_irq_enter_critical_section");

    locate_func(0x20e23bd5, 0xdf3f03f5, true, "_read_counter_phys_ctl_reg_el0");

    locate_func(0xdf3f03f5, 0x20e23bd5, true, "_write_counter_phys_ctl_reg_el0");

    locate_func(hex_set(2817, 0x090100b9, 0x080140f9), hex_set(2817, 0x1f510071, 0xc81040f9), false, "_verify_signature_rsa");

    locate_func(0xdf3f03d5, 0x20e21bd5, true, "_write_cntp_ctl_el0");

    locate_func(0x20e23bd5, 0xdf3f03d5, true, "_read_cntp_ctl_el0");

    locate_func(0xc0035fd6, 0x401018d5, true, "_write_cpacr_el1");

    locate_func(0xc0035fd6, 0x401038d5, true, "_read_cpacr_el1");

    if (version >= 3406) {
      locate_func(0xc0035fd6, 0x001038d5, true, "_read_sctlr_el1");

      locate_func(0xc0035fd6, 0x00a218d5, true, "_write_mair_el1");

      locate_func(0xc0035fd6, 0x402018d5, true, "_write_tcr_el1");
    } // use iBootPatcher and remove the condition.

    locate_func(hex_set(3406, 0x170080d2, 0x3f810071),
      hex_set(3406, 0xea079f1a, 0xe8024039), false, "_contains_boot_arg");

    if (version < 6603) locate_func(0xff830091, 0x0800088b, false, "_alloc_kernel_mem"); // iOS 10+
    
    insn_set(insn,
      0x60023fd6, 0xa0023fd6, 0x80023fd6, 0xe00315aa, 0x80023fd6);
    locate_func(insn, hex_set(5540, 0x03008052, 0x010000d4), false, "_prepare_and_jump");

    locate_func(0x63040091, 0x01014079, false, "_verify_pkcs1_sig");

    locate_func(0x9f3f03d5, 0x1f7508d5, true, "__invalidate_cache_pou");

    locate_func(0xe0039f5a, 0xe30316aa, false, "_aes_crypto_cmd");

    locate_func(0x9f3f03d5, hex_set(3406, 0x00101ed5, 0x001018d5), true, "_arm_write_sctlr");

    locate_func(hex_set(6603, 0x00815fb8, 0x14815fb8), 0xf30302aa, false, "_boot_object");

    locate_func(0x9f3f03d5, hex_set(3406, 0x1f870ed5, 0x1f8708d5), true, "_reload_cache"); // iBootPatcher
  }

  insn_set(insn,
    0x480100f9, 0x880300f9, 0x0801138b, 0x3f0100f1, 0x0801138b);
  locate_func(hex_set(5540, 0x010080d2, 0xd602889a), insn, false, "_macho_load");

  locate_func(0xdf4303d5, 0x22423bd5, true, "_mmu_kvtop");

  find_libc();

  locate_func(hex_set(4076, 0x20018052, 0x3f0d0071), hex_set(4076, 0x08050011, 0x29050011), false, "_panic");

  return ibot;
}

void usage(char *owo[]) {
  char *ibot = NULL;
  ibot = strrchr(owo[0], '/');
  printf("usage: %s [-f] <iboot> [-e]\n", (ibot ? ibot + 1 : owo[0]));
  printf("\t-f, --find\tfind functions of a decrypted iBoot64.\n");
  printf("\t-e, --extra\ttry to find more iBoot functions.\n");
}

int main(int argc, char *argv[]) {
  FILE *fd = NULL;

  int find = 0, extra = 0;

  if (argc < 3) goto usagend;

  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "-f") || !strcmp(argv[i], "--find")) {
      find = 1;

      if (argv[i+2] != NULL) {
        if (!strcmp(argv[i+2], "-e") || !strcmp(argv[i+2], "--extra")) {
          extra = 1;
          break;
        } else {
          printf("warning: unrecognized argument: %s\n", argv[i+2]);
          goto usagend;
        }
      }

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

    printf("[%s]: detected iBoot-%s!\n", __func__, ibot + 0x286);

    version = atoi(ibot + 0x286);

    base = *(uint64_t *)(ibot + hex_set(6603, 0x318, 0x300));

    printf("[%s]: base_addr = 0x%llx\n", __func__, base);

    if (detect_pac() == true) {
      printf("[%s]: PACed bootloader detected!\n", __func__);
    }

    if (!find_funcs(extra)) return -1;

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