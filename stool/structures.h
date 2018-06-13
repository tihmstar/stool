//
//  structures.h
//  stool
//
//  Created by tihmstar on 12.06.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#ifndef structures_h
#define structures_h
#include "all_stool.h"

#define STATIC_INLINE static inline
#define ATTRIBUTE_PACKED __attribute__ ((packed))

typedef struct{
    char unknown[0x10]; //TODO what are these headers?
    char versionID[14];
    uint16_t unknown2;
} ATTRIBUTE_PACKED Package1Header_t;


typedef struct{
    uint32_t magic;
    uint32_t section0Size;
    uint32_t section0Offset;
    uint32_t _unknown;
    uint32_t section1Size;
    uint32_t section1Offset;
    uint32_t section2Size;
    uint32_t section2Offset;
} ATTRIBUTE_PACKED PK11Header_t;


typedef struct{
    char headerCTR[0x10];
    char section0CTR[0x10];
    char section1CTR[0x10];
    char section2CTR[0x10];
    char section3CTR[0x10];
    char magic[4];
    uint32_t baseOffset;
    uint32_t _zerobytes;
    uint16_t version;
    uint16_t __padding;
    uint32_t section0Size;
    uint32_t section1Size;
    uint32_t section2Size;
    uint32_t section3Size;
    uint32_t section0Offset;
    uint32_t section1Offset;
    uint32_t section2Offset;
    uint32_t section3Offset;
    char section0encSHA256[0x20];
    char section1encSHA256[0x20];
    char section2encSHA256[0x20];
    char section3encSHA256[0x20];
} ATTRIBUTE_PACKED Package2Header_t;
CASSERT(sizeof(Package2Header_t) == 0x100, Package2Header_t_bad_header_size);

typedef struct{
    char signature[0x100];
    Package2Header_t header;
    char body[];
} ATTRIBUTE_PACKED Package2_t;

typedef struct{
    char hash[0x10];
    char rsa_pss_signature[0x100];
} ATTRIBUTE_PACKED obj_signature_t;

typedef struct{
    char __padding_pre[0x0c];
    char keyblob[0xb0];
    char __padding_post[0x08];
} ATTRIBUTE_PACKED switch_customer_data_t;

typedef struct{
    uint32_t version;
    uint32_t start_block;
    uint32_t start_page;
    uint32_t length;
    uint32_t load_addr;
    uint32_t entry_point;
    uint32_t attribute;
    obj_signature_t signature;
} ATTRIBUTE_PACKED bootloader_info_t;

typedef struct{
    char bad_block_table[0x210];
    char bct_key[0x100];
    obj_signature_t bct_signature;
    uint32_t sec_provisioning_key_num_insecure; //always zero
    char sec_provisioning_key[0x20]; //always empty
    switch_customer_data_t customer_data;
    uint32_t odm_data;  //unused
    uint32_t reserved0; //unused
    char random_aes_block[0x10]; //Always empty
    char unique_chip_id[0x10]; //Always empty
    uint32_t boot_data_version; //Set to 0x00210001 (BOOTDATA_VERSION_T210).
    uint32_t block_size_log2; //Always 0x0E.
    uint32_t page_size_log2; //Always 0x09.
    uint32_t partition_size; //Always 0x01000000.
    uint32_t num_param_sets; //Always 0x01.
    uint32_t dev_type;      //Set to 0x04 (dev_type_sdmmc).
    char dev_params[0x40];
    uint32_t num_sdram_sets; //always set to 0x0
    char sdram_params0[0x768];
    char sdram_params1[0x768];
    char sdram_params2[0x768];
    char sdram_params3[0x768];
    uint32_t num_bootloaders; //always 2
    bootloader_info_t bootloader_info[4]; //3 and 4 are empty
    uint8_t enable_fail_back; //always 0
    uint32_t secure_debug_control; //always 0
    uint32_t sec_provisioning_key_num_secure; //always 0
    char reserved2[0x12];
    //0x05 padding
} ATTRIBUTE_PACKED BCT_t;
CASSERT(sizeof(BCT_t) == 0x27FB, BCT_t_bad_header_size);


typedef struct{
    char unused[4];
    uint32_t mod0_offset;
    char padding[8]; //HOMEBREW
} nroStart_t;

typedef struct{
    uint32_t fileOffset;
    uint32_t size;
} segmentHeader_t;

typedef struct{
    uint32_t magic;
    uint32_t formatVersion; //always 0
    uint32_t size;
    uint32_t flags; //unused
    struct{
        segmentHeader_t text;
        segmentHeader_t ro;
        segmentHeader_t data;
    };
    uint32_t bssSize;
    char _reserved[4]; //unused
    char buildID[0x20];
    char _reserved2[8]; //unused
    struct{
        segmentHeader_t apiInfo;
        segmentHeader_t dynstr;
        segmentHeader_t dynsym;
    };
} ATTRIBUTE_PACKED nroHeader_t;
CASSERT(sizeof(nroHeader_t) == 0x70, nroHeader_t_bad_header_size);

#endif /* structures_h */
