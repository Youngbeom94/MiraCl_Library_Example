#define _CRT_SECURE_NO_WARNINGS 

#if 1 //! [Key Generation] ******************************************************************************************

#include <iostream>
#include <fstream>
#include "ecn.h"

using namespace std;

// if MR_STATIC defined, it should be 20

#ifndef MR_NOFULLWIDTH
Miracl precision = 20;
#else
Miracl precision(20, MAXBASE);
#endif

int main()
{
    ifstream common("common.ecs");    /* construct file I/O streams */
    ofstream public_key("public.ecs");
    ofstream private_key("private.ecs");
    int bits, ep;
    miracl* mip = &precision;

    ECn G, W;
    Big a, b, p, q, x, y, d;
    long seed;

    cout << "Enter 9 digit random number seed  = ";
    cin >> seed;
    irand(seed);

    common >> bits;
    mip->IOBASE = 16;
    common >> p >> a >> b >> q >> x >> y;
    mip->IOBASE = 10;

    ecurve(a, b, p, MR_PROJECTIVE);

    if (!G.set(x, y))
    {
        cout << "Problem - point (x,y) is not on the curve" << endl;
        return 0;
    }

    W = G;
    W *= q;

    if (!W.iszero())
    {
        cout << "Problem - point (x,y) is not of order q" << endl;
        return 0;
    }

    /* generate public/private keys */

    d = rand(q);
    //   for (int i=0;i<=10000;i++)
    G *= d;
    ep = G.get(x);
    cout << "public key = " << ep << " " << x << endl;
    public_key << ep << " " << x << endl;
    private_key << d << endl;
    return 0;
}
#endif

#if 0 //! [Signature Generation] ******************************************************************************************
#include <iostream>
#include <cstring>
#include <fstream>
#include "ecn.h"

using namespace std;

#ifndef MR_NOFULLWIDTH
Miracl precision(200, 256);
#else
Miracl precision(50, MAXBASE);
#endif

void strip(char* name)
{ /* strip off filename extension */
    int i;
    for (i = 0; name[i] != '\0'; i++)
    {
        if (name[i] != '.') continue;
        name[i] = '\0';
        break;
    }
}

static Big Hash(ifstream& fp)
{ /* compute hash function */
    char ch, s[20];
    Big h;
    sha sh;
    shs_init(&sh);
    forever
    { /* read in bytes from message file */
        fp.get(ch);
        if (fp.eof()) break;
        shs_process(&sh,ch);
    }
    shs_hash(&sh, s);
    h = from_binary(20, s);
    return h;
}

int main()
{
    ifstream common("common.ecs");    /* construct file I/O streams */
    ifstream private_key("private.ecs");
    ifstream message;
    ofstream signature;
    char ifname[50], ofname[50];
    ECn G;
    Big a, b, p, q, x, y, h, r, s, d, k;
    long seed;
    int bits;
    miracl* mip = &precision;

    /* randomise */
    cout << "Enter 9 digit random number seed  = ";
    cin >> seed;
    irand(seed);

    /* get common data */
    common >> bits;
    mip->IOBASE = 16;
    common >> p >> a >> b >> q >> x >> y;
    mip->IOBASE = 10;

    /* calculate r - this can be done off-line,
       and hence amortized to almost nothing    */
    ecurve(a, b, p, MR_PROJECTIVE);
    G = ECn(x, y);
    k = rand(q);
    G *= k;            /* see ebrick.cpp for technique to speed this up */
    G.get(r);
    r %= q;

    /* get private key of recipient */
    private_key >> d;

    /* get message */
    cout << "file to be signed = ";
    cin >> ifname;
    strcpy(ofname, ifname);
    strip(ofname);
    strcat(ofname, ".ecs");
    message.open(ifname, ios::binary | ios::in);
    if (!message)
    {
        cout << "Unable to open file " << ifname << "\n";
        return 0;
    }
    h = Hash(message);

    /* calculate s */
    k = inverse(k, q);
    s = ((h + d * r) * k) % q;
    signature.open(ofname);
    signature << r << endl;
    signature << s << endl;
    return 0;
}
#endif

#if 0 //! [Signature Verification] ******************************************************************************************
#include <iostream>
#include <fstream>
#include <cstring>
#include "ecn.h"

using namespace std;

#ifndef MR_NOFULLWIDTH
Miracl precision(200, 256);
#else
Miracl precision(50, MAXBASE);
#endif

void strip(char* name)
{ /* strip off filename extension */
    int i;
    for (i = 0; name[i] != '\0'; i++)
    {
        if (name[i] != '.') continue;
        name[i] = '\0';
        break;
    }
}

static Big Hash(ifstream& fp)
{ /* compute hash function */
    char ch, s[20];
    Big h;
    sha sh;
    shs_init(&sh);
    forever
    { /* read in bytes from message file */
        fp.get(ch);
        if (fp.eof()) break;
        shs_process(&sh,ch);
    }
    shs_hash(&sh, s);
    h = from_binary(20, s);
    return h;
}

int main()
{
    ifstream common("common.ecs");    /* construct file I/O streams */
    ifstream public_key("public.ecs");
    ifstream message;
    ifstream signature;
    ECn G, Pub;
    int bits, ep;
    Big a, b, p, q, x, y, v, u1, u2, r, s, h;
    char ifname[50], ofname[50];
    miracl* mip = &precision;

    /* get public data */
    common >> bits;
    mip->IOBASE = 16;
    common >> p >> a >> b >> q >> x >> y;
    mip->IOBASE = 10;
    ecurve(a, b, p, MR_PROJECTIVE);
    G = ECn(x, y);
    /* get public key of signer */
    public_key >> ep >> x;
    Pub = ECn(x, ep);         // decompress
/* get message */
    cout << "signed file = ";
    cin.sync();
    cin.getline(ifname, 13);
    strcpy(ofname, ifname);
    strip(ofname);
    strcat(ofname, ".ecs");
    message.open(ifname, ios::binary | ios::in);
    if (!message)
    { /* no message */
        cout << "Unable to open file " << ifname << "\n";
        return 0;
    }
    h = Hash(message);

    signature.open(ofname, ios::in);
    if (!signature)
    { /* no signature */
        cout << "signature file " << ofname << " does not exist\n";
        return 0;
    }
    signature >> r >> s;
    if (r >= q || s >= q)
    {
        cout << "Signature is NOT verified\n";
        return 0;
    }
    s = inverse(s, q);
    u1 = (h * s) % q;
    u2 = (r * s) % q;

    G = mul(u2, Pub, u1, G);
    G.get(v);
    v %= q;
    if (v == r) cout << "Signature is verified\n";
    else      cout << "Signature is NOT verified\n";
    return 0;
}
#endif
