#define _CRT_SECURE_NO_WARNINGS 
#include <iostream>
#include <ctime>
#include "big.h"
#include "ecn.h"

//! NIST p192 bits ECC curve prime
char* ecp = (char*)"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF";

//! NIST p192 bits ECC curve parameter b
char* ecb = (char*)"64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1";

//! NIST p192 bits ECC curve point of prime order (x,y)
char* ecx = (char*)"188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012";
char* ecy = (char*)"07192B95FFC8DA78631011ED6B24CDD573F977A11E794811";

Miracl precision = 50;
miracl* mip = &precision;

int main()
{
	time_t seed;
	Big a, b, p, x, y, num;
	ECn point1, point2, point3;

	time(&seed);
	irand((long)seed);

	//! ECC init
	a = -3;
	mip->IOBASE = 16;
	b = ecb;
	p = ecp;
	ecurve(a, b, p, MR_BEST);

	x = ecx;
	y = ecy;
	point1 = ECn(x, y);

	point2 = point1;
	point3 = point1;
	cout << "point1 : " << point1 << endl;

	num = 2;
	point2 *= num;
	cout << "point2 : " << point2 << endl;

	point3 += point1;
	cout << "point3 : " << point3 << endl;

	num = rand(160, 2);
	point1 *= num;
	cout << "num : " << num << endl;
	cout << "num * point1 : " << point1 << endl;

	return 0;
}


