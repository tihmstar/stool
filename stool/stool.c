//
//  stool.c
//  stool
//
//  Created by tihmstar on 18.05.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#include "all_stool.h"
#include "stool.h"
#include <string.h>

#define STATIC_INLINE static inline
#define ATTRIBUTE_PACKED __attribute__ ((packed))

#define unusualPrintField(field,expected,print) if (field != expected) {printf("[Unusual] %s : 0x%08x\n",print,field);}
#define unusualPrintBuf(field,expected,print) if (memcmp(field,expected,sizeof(expected)-1)) {printf("[Unusual] %s : ",print); printHex(field,sizeof(expected)-1);printf("\n");}
#define unusualEmptyPrintBuf(field,emptySize,print)\
do { for (int i=0; i<emptySize; i++){ if (field[i]){printf("[Unusual] %s : ",print); printHex(field,emptySize);printf("\n");break;} }} while (0)


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


int isBufEmpty(const void *buf, size_t size){
    while (size--) {
        if (((uint8_t*)buf)[size])
            return 0;
    }
    return 1;
}

void printHex(const char *str, size_t size){
#define width 0x28
    if (isBufEmpty(str, size)) {
        printf("(empty[0x%02zx])",size);
    }else{
        int isMultiline = 0;
        int64_t printSize = 0;
        for (int i=0; (printSize= (size-(i+width)))>0; i+=width) {
            if (printSize>width){
                if (!isMultiline) {
                    printf("\n");
                    isMultiline = 1;
                }
                printSize = width;
            }
            if (isMultiline) {
                printf("\t");
            }
            for (int j=0;printSize--;j++) printf("%02x",*(unsigned char *)(str+i+j));
            printf("\n");
        }
        
    }
}

#pragma mark list
int package2List(const char *buf, size_t bufSize){
    int err = 0;
    Package2_t *pkg2 = NULL;
    
    assure(bufSize >= sizeof(Package2_t));
    pkg2 = (Package2_t*)buf;
    
    printf("\n----Package2----\n");
    printf("Magic      : %.4s\n",pkg2->header.magic);
    assure(*(uint32_t*)pkg2->header.magic == *(uint32_t*)"PK21");
    printf("Base offset: 0x%08x\n",pkg2->header.baseOffset);
    printf("Version    : 0x%08x\n",pkg2->header.version);
    if (pkg2->header._zerobytes)
        printf("zerobytes  : 0x%08x\n",pkg2->header._zerobytes);
    
    printf("[Section 0]\n");
    printf("Offset : 0x%08x\n",pkg2->header.section0Offset);
    printf("Size   : 0x%08x\n",pkg2->header.section0Size);
    printf("CTR    : ");printHex(pkg2->header.section0CTR,0x10);printf("\n");
    printf("SHA256 : ");printHex(pkg2->header.section0encSHA256,0x20);printf("\n");

    printf("[Section 1]\n");
    printf("Offset : 0x%08x\n",pkg2->header.section1Offset);
    printf("Size   : 0x%08x\n",pkg2->header.section1Size);
    printf("CTR    : ");printHex(pkg2->header.section1CTR,0x10);printf("\n");
    printf("SHA256 : ");printHex(pkg2->header.section1encSHA256,0x20);printf("\n");

    printf("[Section 2]\n");
    printf("Offset : 0x%08x\n",pkg2->header.section2Offset);
    printf("Size   : 0x%08x\n",pkg2->header.section2Size);
    printf("CTR    : ");printHex(pkg2->header.section2CTR,0x10);printf("\n");
    printf("SHA256 : ");printHex(pkg2->header.section2encSHA256,0x20);printf("\n");

    printf("[Section 3]\n");
    printf("Offset : 0x%08x\n",pkg2->header.section3Offset);
    printf("Size   : 0x%08x\n",pkg2->header.section3Size);
    printf("CTR    : ");printHex(pkg2->header.section3CTR,0x10);printf("\n");
    printf("SHA256 : ");printHex(pkg2->header.section3encSHA256,0x20);printf("\n");

    printf("\n");
    
    
error:
    return err;
}

int printBootloader_info(bootloader_info_t *bldr){
    int err = 0;
    printf("Version         : 0x%08x\n",bldr->version);
    printf("start_block     : 0x%08x\n",bldr->start_block);
    printf("start_page      : 0x%08x\n",bldr->start_page);
    printf("length          : 0x%08x\n",bldr->length);
    printf("load_addr       : 0x%08x\n",bldr->load_addr);
    printf("entry_point     : 0x%08x\n",bldr->entry_point);
    printf("attribute       : 0x%08x\n",bldr->attribute);
    printf("bootloader_hash : ");printHex(bldr->signature.hash, sizeof(bldr->signature.hash));printf("\n");
    printf("bootloader_rsa_pss_signature: ");printHex(bldr->signature.rsa_pss_signature, sizeof(bldr->signature.rsa_pss_signature));printf("\n");

error:
    return err;
}

int bctList(const char *buf, size_t bufSize){
    int err = 0;
    BCT_t *bct = NULL;

    assure(bufSize >= sizeof(BCT_t));
    bct = (BCT_t*)buf;
    
    printf("\n----BCT----\n");
    unusualPrintField(bct->sec_provisioning_key_num_insecure, 0, "sec_provisioning_key_num_insecure");
    unusualEmptyPrintBuf(bct->sec_provisioning_key,0x20,"sec_provisioning_key");
    printf("customer keyblob : ");printHex(bct->customer_data.keyblob,sizeof(bct->customer_data.keyblob));
    unusualEmptyPrintBuf(bct->random_aes_block, 0x10,"sec_provisioning_key");
    unusualEmptyPrintBuf(bct->unique_chip_id, 0x10,"unique_chip_id");
    unusualPrintField(bct->boot_data_version, 0x00210001, "boot_data_version");
    unusualPrintField(bct->block_size_log2, 0xe, "block_size_log2");
    unusualPrintField(bct->page_size_log2, 0x9, "page_size_log2");
    unusualPrintField(bct->partition_size, 0x01000000, "partition_size");
    unusualPrintField(bct->num_param_sets, 0x1, "num_param_sets");
    unusualPrintField(bct->dev_type, 0x4, "dev_type");
    //not printing dev_params cuz lazy
    unusualPrintField(bct->num_sdram_sets, 0x0, "num_sdram_sets");
    //sdram_params0 should be default values
    //sdram_params1 should be default values
    //sdram_params2 should be default values
    //sdram_params3 should be default values
    unusualPrintField(bct->num_bootloaders, 0x2, "num_bootloaders");
    for (int i=0; i<4; i++) {
        printf("[bootloader%d_info]",i);
        int empty = 1;
        for (int j=0; j<sizeof(bootloader_info_t); j++) {
            if (((uint8_t*)&bct->bootloader_info[i])[j]) {
                printf("\n");
                printBootloader_info(&bct->bootloader_info[i]);
                empty = 0;
                break;
            }
        }
        if (empty) {
            printf(" is empty\n");
        }
    }
    unusualPrintField(bct->enable_fail_back, 0, "enable_fail_back");
    unusualPrintField(bct->secure_debug_control, 0, "secure_debug_control");
    unusualPrintField(bct->sec_provisioning_key_num_secure, 0, "sec_provisioning_key_num_secure");
    
error:
    return err;
}

#pragma mark extract
int package2GetSection(const char *buf, size_t bufSize, int selectedSection, const char **section, size_t *sectionSize){
    int err = 0;
    
    Package2_t *pkg2 = NULL;
    
    assure(bufSize >= sizeof(Package2_t));
    pkg2 = (Package2_t*)buf;
    assure(*(uint32_t*)pkg2->header.magic == *(uint32_t*)"PK21");
    
    switch (selectedSection) {
        case 0:
            *section = pkg2->body;
            *sectionSize = pkg2->header.section0Size;
            break;
        case 1:
            *section = pkg2->body+pkg2->header.section0Size;
            *sectionSize = pkg2->header.section1Size;
            break;
        case 2:
            *section = pkg2->body+pkg2->header.section0Size + pkg2->header.section1Size;
            *sectionSize = pkg2->header.section2Size;
            break;
        case 3:
            *section = pkg2->body+pkg2->header.section0Size + pkg2->header.section1Size + pkg2->header.section2Size;
            *sectionSize = pkg2->header.section3Size;
            break;

        default:
            reterror("Unknown section %d",selectedSection);
            break;
    }
    
error:
    return err;
}




//
