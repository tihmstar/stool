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
#define retassure(a, errStr ...) do{ if ((a) == 0){err=-(__LINE__); error(errStr); goto error;} }while(0)
#define reterror(estr ...) do{error(estr);err=-(__LINE__); goto error; }while(0)

//statis assert
#define CASSERT(predicate, file) _impl_CASSERT_LINE(predicate,__LINE__,file)

#define _impl_PASTE(a,b) a##b
#define _impl_CASSERT_LINE(predicate, line, file) \
typedef char _impl_PASTE(assertion_failed_##file##_,line)[2*!!(predicate)-1];


#endif /* all_stool_h */
