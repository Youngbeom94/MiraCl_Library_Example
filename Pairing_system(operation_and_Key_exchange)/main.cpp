#include <iostream>
#include <ctime>
#define MR_PAIRING_BN
#define AES_SECURITY 128
#include "pairing_3.h" //! 헤더를 사용하기 위해서는 프로젝트-> 설정 -> 속성 C/C++ /일반/ 추가포함디렉터리에서 MIRACL-master/source/pairing 디렉터리를 추가해야 합니다.

#if 0 //! Basic Pairing Operation
int main() {

	PFC pfc(AES_SECURITY);
	time_t seed;
	G1 P, aP, bP, abP;
	G2 Q, bQ, aQ;
	Big a, b;
	GT aP_bQ, bP_aQ, abP_Q, P_Q_ab;

	pfc.random(P);
	pfc.hash_and_map(Q, (char*)"I want to play Cyberpunk 2077");
	pfc.random(a);
	pfc.random(b);

	cout << "P : " << P.g << endl;
	cout << "P : " << Q.g << '\n'<< endl;
	cout << "a : " << a << endl;
	cout << "b : " << b << '\n' << endl;

	aP = pfc.mult(P, a);
	bQ = pfc.mult(Q, b);
	aP_bQ = pfc.pairing(bQ, aP); //e(aP, bQ)
	//cout << "e(aP, bQ) = " << aP_bQ.g <<  endl;
	cout << "e(aP, bQ) = " << pfc.hash_to_aes_key(aP_bQ) <<  endl;


	bP = pfc.mult(P, b);
	aQ = pfc.mult(Q, a);
	bP_aQ = pfc.pairing(aQ, bP); //e(bP, aQ)
	cout << "e(bP, aQ) = " << pfc.hash_to_aes_key(bP_aQ) << endl;

	abP = pfc.mult(bP, a);
	abP_Q = pfc.pairing(Q, abP); //e(abP, Q)
	cout << "e(abP, Q) = " << pfc.hash_to_aes_key(abP_Q) << endl;

	P_Q_ab = pfc.pairing(Q, P); //e(P,Q)
	P_Q_ab = pfc.power(P_Q_ab, a); //e(P,Q)^a
	P_Q_ab = pfc.power(P_Q_ab, b); //e(P,Q)^ab
	cout << "e(P,Q)^ab = " << pfc.hash_to_aes_key(P_Q_ab) << endl;

	return 0;
}
#endif


#if 1 //! Key Exchange using Pairing system
int main() {

	PFC pfc(AES_SECURITY);
	time_t seed;
	G1 Alice, sA;
	G2 Server, sS;
	GT res, sp, ap;
	Big ss, s, a;

	time(&seed);
	irand((long)seed);
	pfc.random(ss); // TA's super-secret

	cout << "Mapping Server ID to point" << endl;
	pfc.hash_and_map(Server, (char*)"Server");
	
	cout << "Mapping Alice ID to point" << endl;
	pfc.hash_and_map(Alice, (char*)"Alice");

	cout << "Alice and Server visit Trusted Authority" << endl;

	sS = pfc.mult(Server,ss);
	sA = pfc.mult(Alice, ss);

	cout << "Alice and Server Key Exchange" << endl;

	pfc.random(a); // Alice's random number
	pfc.random(s); // Alice's random number

	res = pfc.pairing(Server, sA);
	if (!pfc.member(res))
	{
		cout << "Wrong gropu oreder - aborting" << endl;
		exit(0);
	}
	ap = pfc.power(res, a);
	res = pfc.pairing(sS, Alice);
	if (!pfc.member(res))
	{
		cout << "Wrong gropu oreder - aborting" << endl;
		exit(0);
	}

	sp = pfc.power(res, s);
	cout << "Alice Key= " << pfc.hash_to_aes_key(pfc.power(sp,a)) << endl;
	cout << "Server Key= " << pfc.hash_to_aes_key(pfc.power(ap, s)) << endl;

	return 0;
}
#endif