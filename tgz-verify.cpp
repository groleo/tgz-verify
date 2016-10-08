#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <axTLS/crypto.h>
#include <axTLS/crypto_misc.h>

class Goopa
{
private:
    int _fd;
    off_t _sig_off;
    off_t _sizeof_sig;
    off_t _sizeof_dgst;
    off_t _sizeof_pkcs_mark;
    const char* _tgz_name;
    const char* _tgz_basename;
    const char* _key_name;
private:
    uint8_t* _sig=nullptr;
    uint8_t* _dgstD=nullptr;
    uint8_t* _dgstC=nullptr;
    const off_t _sizeof_pkcs_modulo = 256;

public:
    Goopa(const char* t, const char* k)
        : _tgz_name(t)
        , _tgz_basename(basename(t))
        , _key_name(k)
    {
        Clean();
    }
    bool Init()
    {
        assert(_tgz_name!=nullptr);

        _fd = open(_tgz_name, O_RDONLY);
        if (_fd==-1)
        {
            perror("Failed to open input file");
            return false;
        }

        _sig_off = (off_t)-1;

        _sizeof_pkcs_mark = strlen("PKCSSIG()= ") + strlen(_tgz_basename);
        _sizeof_dgst = strlen("SHA256()= ") + strlen(_tgz_basename) + SHA256_SIZE*2;
        _sizeof_sig = _sizeof_pkcs_mark + _sizeof_pkcs_modulo;
        free(_sig); _sig = nullptr;
        free(_dgstD); _dgstD = nullptr;
        free(_dgstC); _dgstC = nullptr;
        return true;
    }
    void Clean()
    {
        if (_fd>-1) close(_fd);

        _fd=-1;
        _sig_off=(off_t)-1;
        _sizeof_sig=(off_t)-1;
        _sizeof_dgst=(off_t)-1;
        _sizeof_pkcs_mark=(off_t)-1;
        _sig_off = (off_t)-1;
        free(_sig); _sig = nullptr;
        free(_dgstD); _dgstD = nullptr;
        free(_dgstC); _dgstC = nullptr;
    }
    bool ExtractSignature()
    {
        assert(_sig_off==(off_t)-1);
        assert(_fd!=-1);
        assert(_sizeof_sig!=(off_t)-1);
        assert(_sig==nullptr);
        assert(_sizeof_pkcs_modulo!=(off_t)-1);
        assert(_sizeof_pkcs_mark!=(off_t)-1);

        _sig_off = lseek(_fd, -_sizeof_sig, SEEK_END);
        if (_sig_off==(off_t)-1)
        {
            perror("Failed to seek the signature");
            return false;
        }

        uint8_t *mrk_sig = (uint8_t*)calloc(_sizeof_sig, sizeof(uint8_t));

        int rv = read(_fd, mrk_sig, _sizeof_sig);
        if (rv<=0)
        {
            perror("failed to open signature len");
            free(mrk_sig);
            return false;
        }

        _sig = (uint8_t*)calloc(_sizeof_pkcs_modulo, sizeof(uint8_t));
        memcpy(_sig, mrk_sig + _sizeof_pkcs_mark, _sizeof_pkcs_modulo);

        free(mrk_sig);
        return true;
    }

    bool DecryptDigest()
    {
        int len = 0;
        uint8_t *public_key = nullptr;
        int rv;
        X509_CTX x509_ctx = {0};
        int offset = 0;

        assert(_key_name!=nullptr);
        assert(_dgstD==nullptr);
        assert(_sizeof_pkcs_modulo!=(off_t)-1);
        assert(_sig!=nullptr);

        len = get_file(_key_name, &public_key);
        if (len<=0)
        {
            fprintf(stderr, "failed to open public-key len\n");
            return false;
        }

        rv = asn1_public_key(public_key, &offset, &x509_ctx);
        if (rv!=X509_OK)
        {
            fprintf(stderr, "unable to extract public key\n");
            return false;
        }

        _dgstD = (uint8_t*)calloc(_sizeof_pkcs_modulo,sizeof(uint8_t));
        rv = RSA_decrypt(x509_ctx.rsa_ctx, _sig, _dgstD, _sizeof_pkcs_modulo, 0);
        if (rv<=0)
        {
            fprintf(stderr, "Failed to decrypt digest\n");
            return false;
        }

        RSA_free(x509_ctx.rsa_ctx);
        return true;
    }
    bool ComputeDigest()
    {
        int rv=0;
        uint8_t buf[512];
        SHA256_CTX sha256_ctx={0};
        uint8_t sha256_dgst[SHA256_SIZE]={0};

        assert(_fd!=-1);
        assert(_sig_off!=(off_t)-1);
        assert(_dgstC==nullptr);

        if (lseek(_fd, 0, SEEK_SET)==(off_t)-1)
        {
            perror("Failed to seek the signature");
            return false;
        }

        SHA256_Init(&sha256_ctx);
        while (_sig_off>0)
        {
            if (_sig_off<rv||_sig_off< (off_t)sizeof(buf))
                rv=read(_fd,buf,_sig_off);
            else
                rv=read(_fd,buf,sizeof(buf));

            if (rv<0)
            {
                perror("Failed to read signed file");
                return false;
            }

            if (rv==0)
            {
                fprintf(stderr,"eof reached\n");
                return false;
            }
            SHA256_Update(&sha256_ctx, buf, rv);
            _sig_off -= rv;
        }
        SHA256_Final(sha256_dgst, &sha256_ctx);

        _dgstC = (uint8_t*)calloc(_sizeof_dgst,sizeof(uint8_t));

        int o = sprintf((char*)_dgstC, "SHA256(%s)= ",_tgz_basename);
        for (int i=0; i<SHA256_SIZE; ++i)
        {
            sprintf((char*)_dgstC+o+i*2, "%02x", sha256_dgst[i]);
        }
        return true;
    }
    void printDgst(uint8_t *dgst)
    {
        for (int i=0; i<_sizeof_dgst; ++i)
            printf("%c",dgst[i]);
        printf("\n");
    }
    bool CompareDigests()
    {
        assert(_dgstD!=nullptr);
        assert(_dgstC!=nullptr);
        assert(_sizeof_dgst!=(off_t)-1);
        for (int i=0;i<_sizeof_dgst; ++i)
        {
            if (_dgstD[i] != _dgstC[i])
            {
                fprintf(stderr, "Verification Failure idx\n");
                printDgst(_dgstD);
                printDgst(_dgstC);
                return false;
            }
        }
        return true;
    }
};




int main(int argc, char* argv[])
{
    if (argc!=3)
    {
        fprintf(stderr, "Usage: verify signed-tgz public-key\n");
        exit(-1);
    }

    const char* tgzfile = argv[1];
    const char* keyfile = argv[2];

    Goopa g = Goopa(tgzfile, keyfile);

    if ( ! g.Init())
        return -1;

    if ( ! g.ExtractSignature())
        return -1;

    if ( ! g.DecryptDigest())
        return -1;

    if ( ! g.ComputeDigest())
        return -1;

    if ( ! g.CompareDigests())
        return -1;

    return 0;
}
