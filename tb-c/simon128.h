/* 
 * Following code copied (with minor changes) from:
 * "SIMON and SPECK Implementation Guide", Ray Beaulieu, Douglas Shors, Jason Smith, Stefan Treatman-Clark, Bryan Weeks, Louis Wingers, June 26 2018
 * https://nsacyber.github.io/simon-speck/implementations/ImplementationGuide.pdf
 * All rights belong to the respective owners.
 *
 */

#ifndef SIMON128_H
#define SIMON128_H

#include "definitions.h"

#define f64(x) ((ROTL64(x,1) & ROTL64(x,8)) ^ ROTL64(x,2))
#define R64x2(x,y,k1,k2) (y^=f64(x), y^=k1, x^=f64(y), x^=k2)

void Simon128128KeySchedule(u64 K[],u64 rk[])
{
    u64 i,B=K[1],A=K[0];
    u64 c=0xfffffffffffffffcLL, z=0x7369f885192c0ef5LL;
    for(i=0;i<64;){
        rk[i++]=A; A^=c^(z&1)^ROTR64(B,3)^ROTR64(B,4); z>>=1;
        rk[i++]=B; B^=c^(z&1)^ROTR64(A,3)^ROTR64(A,4); z>>=1;
    }
    rk[64]=A; A^=c^1^ROTR64(B,3)^ROTR64(B,4);
    rk[65]=B; B^=c^0^ROTR64(A,3)^ROTR64(A,4);
    rk[66]=A; rk[67]=B;
}

void Simon128128Encrypt(u64 Pt[],u64 Ct[],u64 rk[])
{
    u64 i;
    Ct[0]=Pt[0]; Ct[1]=Pt[1];
    for(i=0;i<68;i+=2) R64x2(Ct[1],Ct[0],rk[i],rk[i+1]);
}

void Simon128128Decrypt(u64 Pt[],u64 Ct[],u64 rk[])
{
    int i;
    Pt[0]=Ct[0]; Pt[1]=Ct[1];
    for(i=67;i>=0;i-=2) R64x2(Pt[0],Pt[1],rk[i],rk[i-1]);
}

void Simon128192KeySchedule(u64 K[],u64 rk[])
{
    u64 i,C=K[2],B=K[1],A=K[0];
    u64 c=0xfffffffffffffffcLL, z=0xfc2ce51207a635dbLL;
    for(i=0;i<63;){
        rk[i++]=A; A^=c^(z&1)^ROTR64(C,3)^ROTR64(C,4); z>>=1;
        rk[i++]=B; B^=c^(z&1)^ROTR64(A,3)^ROTR64(A,4); z>>=1;
        rk[i++]=C; C^=c^(z&1)^ROTR64(B,3)^ROTR64(B,4); z>>=1;
    }
    rk[63]=A; A^=c^1^ROTR64(C,3)^ROTR64(C,4);
    rk[64]=B; B^=c^0^ROTR64(A,3)^ROTR64(A,4);
    rk[65]=C; C^=c^1^ROTR64(B,3)^ROTR64(B,4);
    rk[66]=A; rk[67]=B; rk[68]=C;
}

void Simon128192Encrypt(u64 Pt[],u64 Ct[],u64 rk[])
{
    u64 i,t;
    Ct[0]=Pt[0]; Ct[1]=Pt[1];
    for(i=0;i<68;i+=2) R64x2(Ct[1],Ct[0],rk[i],rk[i+1]);
    t=Ct[1]; Ct[1]=Ct[0]^f64(Ct[1])^rk[68]; Ct[0]=t; // <- "f" -> f64
}

void Simon128192Decrypt(u64 Pt[],u64 Ct[],u64 rk[])
{
    int i;
    u64 t;
    Pt[0]=Ct[0]; Pt[1]=Ct[1];
    t=Pt[0]; Pt[0]=Pt[1]^f64(Pt[0])^rk[68]; Pt[1]=t;  // <- "f" -> f64
    for(i=67;i>=0;i--) {
        t=Pt[0];
        Pt[0]=Pt[1]^f64(Pt[0])^rk[i];
        Pt[1]=t;
    }
}

void Simon128256KeySchedule(u64 K[],u64 rk[])
{
    u64 i,D=K[3],C=K[2],B=K[1],A=K[0];
    u64 c=0xfffffffffffffffcLL, z=0xfdc94c3a046d678bLL;
    for(i=0;i<64;){
        rk[i++]=A; A^=c^(z&1)^ROTR64(D,3)^ROTR64(D,4)^B^ROTR64(B,1); z>>=1;
        rk[i++]=B; B^=c^(z&1)^ROTR64(A,3)^ROTR64(A,4)^C^ROTR64(C,1); z>>=1;
        rk[i++]=C; C^=c^(z&1)^ROTR64(B,3)^ROTR64(B,4)^D^ROTR64(D,1); z>>=1;
        rk[i++]=D; D^=c^(z&1)^ROTR64(C,3)^ROTR64(C,4)^A^ROTR64(A,1); z>>=1;
    }
    rk[64]=A; A^=c^0^ROTR64(D,3)^ROTR64(D,4)^B^ROTR64(B,1);
    rk[65]=B; B^=c^1^ROTR64(A,3)^ROTR64(A,4)^C^ROTR64(C,1);
    rk[66]=C; C^=c^0^ROTR64(B,3)^ROTR64(B,4)^D^ROTR64(D,1);
    rk[67]=D; D^=c^0^ROTR64(C,3)^ROTR64(C,4)^A^ROTR64(A,1);
    rk[68]=A; rk[69]=B; rk[70]=C; rk[71]=D;
}

void Simon128256Encrypt(u64 Pt[],u64 Ct[],u64 rk[])
{
    u64 i;
    Ct[0]=Pt[0]; Ct[1]=Pt[1];
    for(i=0;i<72;i+=2) R64x2(Ct[1],Ct[0],rk[i],rk[i+1]);
}

void Simon128256Decrypt(u64 Pt[],u64 Ct[],u64 rk[])
{
    int i;
    Pt[0]=Ct[0]; Pt[1]=Ct[1];
    for(i=71;i>=0;i-=2) R64x2(Pt[0],Pt[1],rk[i],rk[i-1]);
}

#endif // SIMON128_H
