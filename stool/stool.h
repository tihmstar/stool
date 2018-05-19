//
//  stool.h
//  stool
//
//  Created by tihmstar on 18.05.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#ifndef stool_h
#define stool_h

#include <stdio.h>
#include <stdint.h>

int package2List(const char *buf, size_t bufSize);
int package2GetSection(const char *buf, size_t bufSize, int selectedSection, const char **section, size_t *sectionSize);


#endif /* stool_h */
