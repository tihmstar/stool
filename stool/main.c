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

static struct option longopts[] = {
    { "help",           no_argument,        NULL, 'h' },
    { "list",           no_argument,        NULL, 'l' },
    { "package1",       no_argument,        NULL, '1' },
    { "package2",       no_argument,        NULL, '2' },
    { "section",        required_argument,  NULL, 's' },
    { "extract",        required_argument,  NULL, 'e' },
    { NULL, 0, NULL, 0 }
};

void cmd_help(){
    printf("Usage: stool [OPTIONS] FILE\n");
    printf("Parse nintendo switch binary files\n\n");
    
    printf("  -h, --help\t\t\tprints usage information\n");
    printf("  -l, --list\t\t\tlist sections (needs type)\n");
    printf("  -1, --package1\t\tmark file as PACKAGE1 file\n");
    printf("  -2, --package2\t\tmark file as PACKAGE1 file\n");
    printf("  -s, --section SECTION\t\tselect section\n");
    printf("  -e, --extract DSTPATH\t\textract to file\n");

    printf("\n");
}

enum filetype{
    kFileTypeUndefined  = 0,
    kFileTypePackage1   = 1,
    kFileTypePackage2   = 2
};

#define FLAG_LIST_SECTIONS    1 << 0

int main(int argc, const char * argv[]) {
    printf("Version: " STOOL_VERSION_COMMIT_SHA " - " STOOL_VERSION_COMMIT_COUNT "\n");
    int err = 0;
    int optindex = 0;
    int opt = 0;
    
    long flags = 0;
    enum filetype fileType = kFileTypeUndefined;
    int section = -1;
    
    const char *fileName = NULL;
    const char *extractFileName = NULL;
    
    size_t fileBufSize = 0;
    char *fileBuf = NULL;
    
    while ((opt = getopt_long(argc, (char* const *)argv, "hl12s:e:", longopts, &optindex)) > 0) {
        switch (opt) {
            case 'l':
                flags |= FLAG_LIST_SECTIONS;
                break;
            
            case '1':
            case '2':
                assure(fileType == kFileTypeUndefined);
                fileType = opt-'0';
                break;
            case 's':
                section = atoi(optarg);
                break;
            case 'e':
                extractFileName = optarg;
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
        reterror("Unexpected end of arguments");
    }
    
    assure(fileName);
    assure(fileBuf = readFromFile(fileName, &fileBufSize));
    
    if (flags & FLAG_LIST_SECTIONS) {
        switch (fileType) {
            case kFileTypePackage2:
                assure(!package2List(fileBuf,fileBufSize));
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
            case kFileTypePackage2:
                assure(!package2GetSection(fileBuf, fileBufSize, section, &sBuf, &sBufSize));
                break;
                
            default:
                reterror("Either the filetype [%d] is undefined or unknown",fileType);
                break;
        }
        
        assure(!writeToFile(extractFileName, sBuf, sBufSize));
        printf("Wrote section to %s\n",extractFileName);
        
    }
    
    
error:
    safeFree(fileBuf);
    if (err)
        error("code %d",err);
    return err;
}
