/* 
 * Following code copied from:
 * "SIMON and SPECK Implementation Guide", Ray Beaulieu, Douglas Shors, Jason Smith, Stefan Treatman-Clark, Bryan Weeks, Louis Wingers, June 26 2018
 * https://nsacyber.github.io/simon-speck/implementations/ImplementationGuide.pdf
 * All rights belong to the respective owners.
 *
 */

#ifndef SIMON64_H
#define SIMON64_H

#include "definitions.h"

#define f32(x) ((ROTL32(x,1) & ROTL32(x,8)) ^ ROTL32(x,2))
#define R32x2(x,y,k1,k2) (y^=f32(x), y^=k1, x^=f32(y), x^=k2)

void Simon6496KeySchedule(u32 K[],u32 rk[])
{
    u32 i,c=0xfffffffc;
    u64 z=0x7369f885192c0ef5LL;
    rk[0]=K[0]; rk[1]=K[1]; rk[2]=K[2];
    for(i=3;i<42;i++){
        rk[i]=c^(z&1)^rk[i-3]^ROTR32(rk[i-1],3)^ROTR32(rk[i-1],4);
        z>>=1;
    }
}

void Simon6496Encrypt(u32 Pt[],u32 Ct[],u32 rk[])
{
    u32 i;
    Ct[1]=Pt[1]; Ct[0]=Pt[0];
    for(i=0;i<42;) R32x2(Ct[1],Ct[0],rk[i++],rk[i++]);
}

void Simon6496Decrypt(u32 Pt[],u32 Ct[],u32 rk[])
{
    int i;
    Pt[1]=Ct[1]; Pt[0]=Ct[0];
    for(i=41;i>=0;) R32x2(Pt[0],Pt[1],rk[i--],rk[i--]);
}

void Simon64128KeySchedule(u32 K[],u32 rk[])
{
    u32 i,c=0xfffffffc;
    u64 z=0xfc2ce51207a635dbLL;
    rk[0]=K[0]; rk[1]=K[1]; rk[2]=K[2]; rk[3]=K[3];
    for(i=4;i<44;i++){
        rk[i]=c^(z&1)^rk[i-4]^ROTR32(rk[i-1],3)^rk[i-3]
        ^ROTR32(rk[i-1],4)^ROTR32(rk[i-3],1);
        z>>=1;
    }
}

void Simon64128Encrypt(u32 Pt[],u32 Ct[],u32 rk[])
{
    u32 i;
    Ct[1]=Pt[1]; Ct[0]=Pt[0];
    for(i=0;i<44;) R32x2(Ct[1],Ct[0],rk[i++],rk[i++]);
}

void Simon64128Decrypt(u32 Pt[],u32 Ct[],u32 rk[])
{
    int i;
    Pt[1]=Ct[1]; Pt[0]=Ct[0];
    for(i=43;i>=0;) R32x2(Pt[0],Pt[1],rk[i--],rk[i--]);
}

#endif // SIMON64_H
