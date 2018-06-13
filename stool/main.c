//
//  main.c
//  stool
//
//  Created by tihmstar on 18.05.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdint.h>
#include <string.h>
#include "all_stool.h"
#include "stool.h"


char *readFromFile(const char *filePath, size_t *fileSize){
    FILE *f = fopen(filePath, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char *ret = (char*)malloc(size);
    if (ret) {
        fread(ret, size, 1, f);
        if (fileSize)
            *fileSize = size;
    }
    fclose(f);
    
    return ret;
}

int writeToFile(const char *filePath, const char *buf, size_t bufSize){
    int err = 0;
    FILE *f = NULL;
    assure(f = fopen(filePath, "w"));
    assure(fwrite(buf, 1, bufSize, f) == bufSize);
    
error:
    if (f){
        fclose(f);
        f = NULL;
    }
    return err;
}

int64_t parseNumber(const char *number){
    const char *numberBK = number;
    int isHex = 0;
    int64_t ret = 0;
    
    //in case hex number only contains digits, specify with 0x1235
    if (strncmp(number, "0x", 2) == 0){
        isHex = 1;
        numberBK = number+2;
    }
    
    while (*number && !isHex) {
        char c = *(number++);
        if (c >= '0' && c<='9') {
            ret *=10;
            ret += c - '0';
        }else{
            isHex = 1;
            ret = 0;
        }
    }
    
    if (isHex) {
        while (*numberBK) {
            char c = *(numberBK++);
            ret *=16;
            if (c >= '0' && c<='9') {
                ret += c - '0';
            }else if (c >= 'a' && c <= 'f'){
                ret += 10 + c - 'a';
            }else if (c >= 'A' && c <= 'F'){
                ret += 10 + c - 'A';
            }else{
                return 0; //ERROR parsing failed
            }
        }
    }
    
    return ret;
}

static struct option longopts[] = {
    { "help",           no_argument,        NULL, 'h' },
    { "list",           no_argument,        NULL, 'l' },
    { "package1",       no_argument,        NULL, '1' },
    { "package2",       no_argument,        NULL, '2' },
    { "bct",            no_argument,        NULL, '0' },
    { "nro",            no_argument,        NULL, 'n' },
    { "section",        required_argument,  NULL, 's' },
    { "base",           required_argument,  NULL, 'b' },
    { "extract",        required_argument,  NULL, 'e' },
    { NULL, 0, NULL, 0 }
};

void cmd_help(){
    printf("Usage: stool [OPTIONS] FILE\n");
    printf("Parse nintendo switch binary files\n\n");
    
    printf("  -h, --help\t\t\tprints usage information\n");
    printf("  -l, --list\t\t\tlist sections (needs type)\n");
    printf("  -1, --package1\t\tmark file as PACKAGE1 file (needs --base for list)\n");
    printf("  -2, --package2\t\tmark file as PACKAGE2 file\n");
    printf("  -b, --base\t\t\tspecify base address\n");
    printf("      --bct \t\t\tmark file as BCT file\n");
    printf("  -n, --nro \t\t\tmark file as NRO file\n");
    printf("  -s, --section SECTION\t\tselect section\n");
    printf("  -e, --extract DSTPATH\t\textract to file\n");

    printf("\n");
}

enum filetype{
    kFileTypeUndefined  = 0,
    kFileTypePackage1   = 1,
    kFileTypePackage2   = 2,
    kFileTypeBCT,
    kFileTypeNRO
};

#define FLAG_LIST_SECTIONS    1 << 0

int main(int argc, const char * argv[]) {
    printf("Version: " STOOL_VERSION_COMMIT_SHA " - " STOOL_VERSION_COMMIT_COUNT "\n");
    int err = 0;
    int optindex = 0;
    char opt = 0;
    
    long flags = 0;
    enum filetype fileType = kFileTypeUndefined;
    int section = -1;
    
    const char *fileName = NULL;
    const char *extractFileName = NULL;
    
    size_t fileBufSize = 0;
    char *fileBuf = NULL;

    uint32_t baseAddr = 0;
    
    while ((opt = getopt_long(argc, (char* const *)argv, "hl12s:e:0b:n", longopts, &optindex)) > 0) {
        switch (opt) {
            case 'l':
                flags |= FLAG_LIST_SECTIONS;
                break;
            
            case '1':
            case '2':
                assure(fileType == kFileTypeUndefined);
                fileType = opt-'0';
                break;
            case 'n':
                assure(fileType == kFileTypeUndefined);
                fileType = kFileTypeNRO;
                break;
            case 's':
                section = atoi(optarg);
                break;
            case 'e':
                extractFileName = optarg;
                break;
            case 'b':
            {
                uint64_t num = parseNumber(optarg);
                assure(num && num < (1UL <<32));
                baseAddr = (uint32_t)num;
            }
                break;
            
            case '0':
            {
                switch (optindex) {
                    case 4://bct
                        assure(fileType == kFileTypeUndefined);
                        fileType = kFileTypeBCT;
                        break;
                        
                    default:
                        cmd_help();
                        goto error;//clean termination
                }
            }
                break;
                
            default:
                cmd_help();
                goto error;//clean termination
        }
    }
    
    
    if (argc-optind == 1) {
        argc -= optind;
        argv += optind;
        
        fileName = argv[0];
    }else{
        cmd_help();
        if (argc == 1)//clean termination
            goto error; //don't print any errors if called without args
        reterror("Unexpected end of arguments");
    }
    
    assure(fileName);
    assure(fileBuf = readFromFile(fileName, &fileBufSize));
    
    if (flags & FLAG_LIST_SECTIONS) {
        switch (fileType) {
            case kFileTypePackage1:
                retassure(baseAddr, "base address required for package1List");
                assure(!package1List(fileBuf,fileBufSize, baseAddr));
                break;
            case kFileTypePackage2:
                assure(!package2List(fileBuf,fileBufSize));
                break;
                
            case kFileTypeBCT:
                assure(!bctList(fileBuf,fileBufSize));
                break;
            case kFileTypeNRO:
                assure(!nroList(fileBuf,fileBufSize));
                break;
                
            default:
                reterror("Either the filetype [%d] is undefined or unknown",fileType);
                break;
        }
    }else if (extractFileName && section != -1){
        const char *sBuf = NULL;
        size_t sBufSize = 0;
        //extract a section
        printf("Extracting section %d\n",section);
        switch (fileType) {
            case kFileTypePackage1:
                retassure(baseAddr, "base address required for package2GetSection");
                assure(!package1GetSection(fileBuf, fileBufSize, baseAddr, section, &sBuf, &sBufSize));
                break;
            case kFileTypePackage2:
                assure(!package2GetSection(fileBuf, fileBufSize, section, &sBuf, &sBufSize));
                break;
                
            default:
                reterror("Either the filetype [%d] is undefined or unknown",fileType);
                break;
        }
        
        assure(!writeToFile(extractFileName, sBuf, sBufSize));
        printf("Wrote section to %s\n",extractFileName);
        
    }else{
        reterror("no operation selected");
    }
    
    
error:
    safeFree(fileBuf);
    if (err)
        error("code %d",err);
    return err;
}
