#include <stdio.h>
#include <iostream>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

extern "C"
{
  #include <sha1.h>
}
using namespace std;


typedef int (*result)(char *);

struct user_info {
        char *company;
        char *dep;
        char *name;
        char *progname;
        result good;
        result bad;
};


int good_guy(char *unused)
{
        printf("Thank you for registering !\n");
        return 0;
}

int bad_guy(char *serial)
{
        printf("Invalid serial %s\n", serial);
        return 1;
}


class CRC32 {
        int poly;
public:
        CRC32 (): poly(0x04C11DB7) {};

        CRC32 (int inipoly)
        {
                poly = inipoly;
        }

        int compute(const string& s)
        {
        unsigned int sr = ~0;
//        unsigned char c;
        int i, j;

        for (auto c : s){
                for (j=0; j<8; j++) {
                        int b = sr >> 31;
                        sr <<= 1;
                        if ((b ^ c) & 1) 
                                sr ^= poly;
                }
        }
        return sr;
        }
};

int compute_key(struct user_info *info) 
{
        unsigned int k_comp, k_dept, k_name, k_progname;
        
        CRC32 custom_crc32;

        k_comp = custom_crc32.compute(string(info->company));
        k_dept = custom_crc32.compute(string(info->dep));
        k_name = custom_crc32.compute(string(info->name));
        k_progname = custom_crc32.compute(string(info->progname));
         
        return k_comp*k_name;
}


char *compute_hash(struct user_info *info, int key, char *buf) 
{
        char *p;
        unsigned char sha1[20];
        int i;

        p = buf;
        p += sprintf(p, "Company     = %s\n", info->company);
        p += sprintf(p, "Department  = %s\n", info->dep);
        p += sprintf(p, "Name        = %s\n", info->name);
        p += sprintf(p, "Station     = %s\n", info->progname);
        p += sprintf(p, "-----------\n");
        p += sprintf(p, "LICENSE KEY = %08x\n", key);

        mbedtls_sha1((unsigned char *)buf, strlen(buf), sha1);

        p += sprintf(p, "SHA-1       = ");
        
        p = buf;
        for (i=0; i<20; i++)
                p += sprintf(p, "%02X", sha1[i]);
        return buf;
}

void usage(void)
{
        std::cerr <<  "Usage: get_key -c company -d department -n name -l license" << std::endl;
        exit(-1);
}

int main(int argc, char *argv[])
{
        unsigned int key;
        char opt, *licence, *provided_lic = NULL;
        char buf[500];
        struct utsname uts;
        struct user_info info;

        info.company = info.name = info.dep = NULL;

        if(argc < 5) {
                printf("Usage: %s company department name licence\n", argv[0]);
                return 1;
        }
        provided_lic = argv[4];
        info.company = argv[1];
        info.dep = argv[2];
        info.name = argv[3];
        info.progname = argv[0];
        info.good = good_guy;
        info.bad = bad_guy;
        key = compute_key(&info);
        licence = compute_hash(&info, key, buf);
        
        std::cout << "Licence=>[" << licence << "]" << std::endl;
        
        int res = strlen(licence)-strlen(provided_lic);
        for (int i = 0; (i < strlen(licence)) && (res ==0); i++)
                res |= licence[i]^provided_lic[i];
        if (res != 0)
                return info.bad(provided_lic);
        else
                return info.good(provided_lic);
}
