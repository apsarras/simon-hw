/* 
 * Following code copied from:
 * "SIMON and SPECK Implementation Guide", Ray Beaulieu, Douglas Shors, Jason Smith, Stefan Treatman-Clark, Bryan Weeks, Louis Wingers, June 26 2018
 * https://nsacyber.github.io/simon-speck/implementations/ImplementationGuide.pdf
 * All rights belong to the respective owners.
 *
 */
#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#include "definitions.h"

void Words32ToBytes(u32 words[],u8 bytes[],int numwords)
{
    int i,j=0;
    for(i=0;i<numwords;i++){
        bytes[j]=(u8)words[i];
        bytes[j+1]=(u8)(words[i]>>8);
        bytes[j+2]=(u8)(words[i]>>16);
        bytes[j+3]=(u8)(words[i]>>24);
    j+=4;
    }
}


void Words64ToBytes(u64 words[],u8 bytes[],int numwords)
{
    int i,j=0;
    for(i=0;i<numwords;i++){
        bytes[j]=(u8)words[i];
        bytes[j+1]=(u8)(words[i]>>8);
        bytes[j+2]=(u8)(words[i]>>16);
        bytes[j+3]=(u8)(words[i]>>24);
        bytes[j+4]=(u8)(words[i]>>32);
        bytes[j+5]=(u8)(words[i]>>40);
        bytes[j+6]=(u8)(words[i]>>48);
        bytes[j+7]=(u8)(words[i]>>56);
        j+=8;
    }
}

void BytesToWords32(u8 bytes[],u32 words[],int numbytes)
{
    int i,j=0;
    for(i=0;i<numbytes/4;i++){
        words[i]=(u32)bytes[j] | ((u32)bytes[j+1]<<8) | ((u32)bytes[j+2]<<16) |
        ((u32)bytes[j+3]<<24); j+=4;
    }
}

void BytesToWords64(u8 bytes[],u64 words[],int numbytes)
{
    int i,j=0;
    for(i=0;i<numbytes/8;i++){
        words[i]=(u64)bytes[j] | ((u64)bytes[j+1]<<8) | ((u64)bytes[j+2]<<16) |
                 ((u64)bytes[j+3]<<24) | ((u64)bytes[j+4]<<32) | ((u64)bytes[j+5]<<40) |
                 ((u64)bytes[j+6]<<48) | ((u64)bytes[j+7]<<56); j+=8;
    }
}

#endif // FUNCTIONS_H