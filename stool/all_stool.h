//
//  all_stool.h
//  stool
//
//  Created by tihmstar on 18.05.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#ifndef all_stool_h
#define all_stool_h

#define error(a ...) printf("[Error] %s: ",__func__),printf(a),printf("\n")
#define warning(a ...) printf("[Warning] %s: ",__func__),printf(a),printf("\n")

#ifdef DEBUG //this is for developing with Xcode
#define STOOL_VERSION_COMMIT_COUNT "Debug"
#define STOOL_VERSION_COMMIT_SHA "Build: " __DATE__ " " __TIME__
#else
#include <config.h>
#endif


#define safeFree(buf) ({if (buf) free(buf), buf = NULL;})
#define assure(a) do{ if ((a) == 0){err=-(__LINE__); goto error;} }while(0)
#define reterror(estr ...) do{error(estr);err=-(__LINE__); goto error; }while(0)


#endif /* all_stool_h */
