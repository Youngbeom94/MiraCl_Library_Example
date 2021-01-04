/*
   Scott's AKE Client/Server testbed

   Compile with modules as specified below

   For MR_PAIRING_CP curve
   cl /O2 /GX ake.cpp cp_pair.cpp zzn2.cpp big.cpp zzn.cpp ecn.cpp miracl.lib

   For MR_PAIRING_MNT curve
   cl /O2 /GX ake.cpp mnt_pair.cpp zzn6a.cpp ecn3.cpp zzn3.cpp zzn2.cpp big.cpp zzn.cpp ecn.cpp miracl.lib

   For MR_PAIRING_BN curve
   cl /O2 /GX ake.cpp bn_pair.cpp zzn12a.cpp ecn2.cpp zzn4.cpp zzn2.cpp big.cpp zzn.cpp ecn.cpp miracl.lib

   For MR_PAIRING_KSS curve
   cl /O2 /GX ake.cpp kss_pair.cpp zzn18.cpp zzn6.cpp ecn3.cpp zzn3.cpp big.cpp zzn.cpp ecn.cpp miracl.lib

   For MR_PAIRING_BLS curve
   cl /O2 /GX ake.cpp bls_pair.cpp zzn24.cpp zzn8.cpp zzn4.cpp zzn2.cpp ecn4.cpp big.cpp zzn.cpp ecn.cpp miracl.lib

   See http://eprint.iacr.org/2002/164

*/

#include <iostream>
#include <ctime>

//********* choose just one of these pairs **********
//#define MR_PAIRING_CP      // AES-80 security   
//#define AES_SECURITY 80

//#define MR_PAIRING_MNT	// AES-80 security
//#define AES_SECURITY 80

#define MR_PAIRING_BN    // AES-128 or AES-192 security
#define AES_SECURITY 128
//#define AES_SECURITY 192

//#define MR_PAIRING_KSS    // AES-192 security
//#define AES_SECURITY 192

//#define MR_PAIRING_BLS    // AES-256 security
//#define AES_SECURITY 256
//*********************************************

#include "pairing_3.h"

int main()
{
	PFC pfc(AES_SECURITY);  // initialise pairing-friendly curve

	time_t seed;
	G1 Alice, Bob, sA, sB;
	G2 B6, Server, sS;
	GT res, sp, ap, bp;
	Big ss, s, a, b;

	time(&seed);
	irand((long)seed);

	pfc.random(ss);    // TA's super-secret 

	cout << "Mapping Server ID to point" << endl;
	pfc.hash_and_map(Server, (char*)"Server");

	cout << "Mapping Alice & Bob ID's to points" << endl;
	pfc.hash_and_map(Alice, (char*)"Alice");
	pfc.hash_and_map(Bob, (char*)"Robert");

	cout << "Alice, Bob and the Server visit Trusted Authority" << endl;

	sS = pfc.mult(Server, ss);
	sA = pfc.mult(Alice, ss);
	sB = pfc.mult(Bob, ss);

	cout << "Alice and Server Key Exchange" << endl;


	pfc.random(a);  // Alice's random number
	pfc.random(s);   // Server's random number

	res = pfc.pairing(Server, sA);

	if (!pfc.member(res))
	{
		cout << "Wrong group order - aborting" << endl;
		exit(0);
	}

	ap = pfc.power(res, a);

	res = pfc.pairing(sS, Alice);

	if (!pfc.member(res))
	{
		cout << "Wrong group order - aborting" << endl;
		exit(0);
	}

	sp = pfc.power(res, s);

	cout << "Alice  Key= " << pfc.hash_to_aes_key(pfc.power(sp, a)) << endl;
	cout << "Server Key= " << pfc.hash_to_aes_key(pfc.power(ap, s)) << endl;

	cout << "Bob and Server Key Exchange" << endl;

	pfc.random(b);   // Bob's random number
	pfc.random(s);   // Server's random number

	res = pfc.pairing(Server, sB);
	if (!pfc.member(res))
	{
		cout << "Wrong group order - aborting" << endl;
		exit(0);
	}
	bp = pfc.power(res, b);

	res = pfc.pairing(sS, Bob);
	if (!pfc.member(res))
	{
		cout << "Wrong group order - aborting" << endl;
		exit(0);
	}

	sp = pfc.power(res, s);

	cout << "Bob's  Key= " << pfc.hash_to_aes_key(pfc.power(sp, b)) << endl;
	cout << "Server Key= " << pfc.hash_to_aes_key(pfc.power(bp, s)) << endl;

	return 0;
}



//
//G1 P, aP, bP, abP;
//G2 Q, bQ, aQ;
//Big a, b;
//GT aP_bQ, bP_aQ, abP_Q, P_Q_ab;
//
//
//
//pfc.random(P);
//pfc.hash_and_map(Q, (char*)"I want to play Cyberpunk 2077");
//
//pfc.random(a);
//pfc.random(b);
//
//cout << "P : " << P.g << endl;
//cout << "Q : " << Q.g << '\n' << endl;
//cout << "a : " << a << endl;
//cout << "b : " << b << '\n' << endl;
//
//
//aP = pfc.mult(P, a);
//bQ = pfc.mult(Q, b);
//aP_bQ = pfc.pairing(bQ, aP); // e(aP, bQ)
////cout << "e(aP, bQ) =  " << aP_bQ.g << endl;
//cout << "e(aP, bQ) =  " << pfc.hash_to_aes_key(aP_bQ) << endl;
//
//bP = pfc.mult(P, b);
//aQ = pfc.mult(Q, a);
//bP_aQ = pfc.pairing(aQ, bP); // e(bP, aQ)
//cout << "e(bP, aQ) =  " << pfc.hash_to_aes_key(bP_aQ) << endl;
//
//abP = pfc.mult(bP, a);
//abP_Q = pfc.pairing(Q, abP); // e(abP, Q)
//cout << "e(abP, Q) =  " << pfc.hash_to_aes_key(abP_Q) << endl;
//
//
//P_Q_ab = pfc.pairing(Q, P); // e(P, Q)
//P_Q_ab = pfc.power(P_Q_ab, a); // e(P, Q)^a
//P_Q_ab = pfc.power(P_Q_ab, b); // e(P, Q)^ab
//cout << "e(P, Q)^ab =  " << pfc.hash_to_aes_key(P_Q_ab) << '\n\n' << endl;
//
//
//G1 p, rp, sp, result_g1;
//G2 h, sh, result_g2;
//GT result_pairing, result_power_pairing;
//Big r, s;
//Big key;
//
//
//
//pfc.hash_and_map(h, (char*)"my name is alice");
//pfc.hash_and_map(p, (char*)"time server");
//
//pfc.random(s);
//pfc.random(r);
//
//sh = pfc.mult(h, s);
//rp = pfc.mult(p, r);
//result_pairing = pfc.pairing(sh, rp);
//key = pfc.hash_to_aes_key(result_pairing);
//cout << "e (sh,rp) =  " << key << endl; printf("\n");
//cout << "e (sh,rp) =  " << pfc.hash_to_aes_key(result_pairing) << endl; printf("\n");
////--------------------------------------------------------------------------------------------------
//
//result_pairing = pfc.pairing(h, p);
//result_power_pairing = pfc.power(result_pairing, r);
//result_power_pairing = pfc.power(result_power_pairing, s);
//cout << "e (h,p)^s*r = " << pfc.hash_to_aes_key(result_power_pairing) << endl; printf("\n");
////--------------------------------------------------------------------------------------------------  
//
//
//sp = pfc.mult(p, s);
//result_pairing = pfc.pairing(h, sp);
//result_power_pairing = pfc.power(result_pairing, r);
//cout << "e (h,sp)^r = " << pfc.hash_to_aes_key(result_power_pairing) << endl; printf("\n");
