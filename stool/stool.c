//
//  stool.c
//  stool
//
//  Created by tihmstar on 18.05.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#include "all_stool.h"
#include "stool.h"


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
//    uint16_t __padding;
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
} Pachage2Header_t;

typedef struct{
    char signature[0x100];
    Pachage2Header_t header;
    char body[];
} Package2_t;

void printHex(const char *str, size_t size){
    while (size--) printf("%02x",*(unsigned char *)str++);
}

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
